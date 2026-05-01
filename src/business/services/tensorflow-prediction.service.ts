import { Injectable, Logger } from '@nestjs/common';
import { InjectConnection } from '@nestjs/mongoose';
import { Connection } from 'mongoose';
import * as tf from '@tensorflow/tfjs';
import { ObjectId } from 'mongodb';
import {
  MonthlyDataPointDto,
  TimeSeriesDataDto,
} from '@/business/dto/business-statistics.dto';
import { InvoiceStatus } from '@/invoices/enums/invoice-status.enum';
import { Invoice } from '@/invoices/schemas/invoice.schema';
import { Product } from '@/products/schemas/product.schema';
import { CacheService } from '@/redis/cache.service';

// ─── Public Types ─────────────────────────────────────────────────────────────

export interface MetricForecast {
  metricName: string;
  historical: MonthlyDataPointDto[];
  predicted: MonthlyDataPointDto[];
}

export interface BusinessForecastResult {
  revenue: TimeSeriesDataDto;
  cogs: TimeSeriesDataDto;
  grossProfit: TimeSeriesDataDto;
  salesVolume: TimeSeriesDataDto;
}

// ─── Internal Types ───────────────────────────────────────────────────────────

// Using existing Invoice, InvoiceLineItem, and Product types from schemas

interface MonthlyAggregate {
  revenue: number;
  cogs: number;
  grossProfit: number;
  unitsSold: number;
}

// ─── Constants ────────────────────────────────────────────────────────────────

const WINDOW_SIZE = 3;
const MIN_DATA_POINTS = 6;
const TRAINING_EPOCHS = 100;
const LEARNING_RATE = 0.01;
const CACHE_TTL_SECONDS = 3600; // 1 hour cache for predictions

@Injectable()
export class TensorflowPredictionService {
  private readonly logger = new Logger(TensorflowPredictionService.name);

  constructor(
    @InjectConnection() private readonly connection: Connection,
    private readonly cacheService: CacheService
  ) {}

  // ─── Public API ─────────────────────────────────────────────────────────────

  /**
   * Main entry point: query real invoice + product data from the tenant DB,
   * build monthly time-series, and forecast future values using TensorFlow.
   *
   * Historical data comes from actual DB records.
   * Predicted data extends the timeline into the future (never mixed).
   * Results are cached for 1 hour to reduce computation overhead.
   */
  async forecastBusinessMetrics(
    businessId: string,
    databaseName: string,
    horizonMonths: number
  ): Promise<BusinessForecastResult> {
    const cacheKey = `tf:forecast:${businessId}:${databaseName}:${horizonMonths}`;

    // Try to get from cache first
    const cached =
      await this.cacheService.get<BusinessForecastResult>(cacheKey);
    if (cached) {
      this.logger.debug(`Forecast cache hit for business ${businessId}`);
      // Return clone to prevent mutation of cached data
      return structuredClone(cached);
    }

    const tenantDb = this.connection.useDb(databaseName, { useCache: true });

    // ── 1. Fetch real invoices (ONLY PAID/PARTIAL = real revenue) ─────────────
    const invoices = await tenantDb
      .collection('invoices')
      .find<Invoice>({
        $or: [
          { issuerBusinessId: new ObjectId(businessId) },
          { issuerBusinessId: businessId },
        ],
        status: { $in: [InvoiceStatus.PAID, InvoiceStatus.PARTIAL] },
      })
      .sort({ issuedDate: 1 })
      .toArray();

    // ── 2. Fetch real products for cost lookup ───────────────────────────────

    const products = await tenantDb
      .collection('products')

      .find<Product>({
        $or: [
          { businessId: new ObjectId(businessId) as unknown as string },
          { businessId: businessId },
        ],
      } as Record<string, unknown>)
      .toArray();

    const productCostMap = new Map<string, number>();
    for (const p of products) {
      productCostMap.set(p._id.toString(), p.cost ?? 0);
    }

    // ── 3. Build monthly aggregates from real line items ─────────────────────
    const monthlyData = this.buildMonthlyTimeSeries(invoices, productCostMap);

    const allMonths = [...monthlyData.keys()].toSorted();

    const revenueMonthly: MonthlyDataPointDto[] = allMonths.map((m) => ({
      date: m,
      value: monthlyData.get(m)!.revenue,
    }));

    const cogsMonthly: MonthlyDataPointDto[] = allMonths.map((m) => ({
      date: m,
      value: monthlyData.get(m)!.cogs,
    }));

    const grossProfitMonthly: MonthlyDataPointDto[] = allMonths.map((m) => ({
      date: m,
      value: monthlyData.get(m)!.grossProfit,
    }));

    const unitsSoldMonthly: MonthlyDataPointDto[] = allMonths.map((m) => ({
      date: m,
      value: monthlyData.get(m)!.unitsSold,
    }));

    // ── 4. Forecast each metric using TensorFlow ─────────────────────────────
    const [
      revenuePredicted,
      cogsPredicted,
      grossProfitPredicted,
      salesVolumePredicted,
    ] = await Promise.all([
      this.forecastMetric(revenueMonthly, horizonMonths),
      this.forecastMetric(cogsMonthly, horizonMonths),
      this.forecastMetric(grossProfitMonthly, horizonMonths),
      this.forecastMetric(unitsSoldMonthly, horizonMonths),
    ]);

    const result: BusinessForecastResult = {
      revenue: { historical: revenueMonthly, predicted: revenuePredicted },
      cogs: { historical: cogsMonthly, predicted: cogsPredicted },
      grossProfit: {
        historical: grossProfitMonthly,
        predicted: grossProfitPredicted,
      },
      salesVolume: {
        historical: unitsSoldMonthly,
        predicted: salesVolumePredicted,
      },
    };

    // Cache the result
    await this.cacheService.set(cacheKey, result, CACHE_TTL_SECONDS);
    this.logger.debug(`Forecast cached for business ${businessId}`);

    return result;
  }

  // ─── Data Processing ────────────────────────────────────────────────────────

  /**
   * Walk through real invoice documents, look up each line item's product cost,
   * and aggregate into monthly buckets.
   *
   * CRITICAL: For PARTIAL invoices, revenue/COGS/units are prorated by payment ratio.
   * For PAID invoices, 100% of values are counted.
   */
  private buildMonthlyTimeSeries(
    invoices: Invoice[],
    productCostMap: Map<string, number>
  ): Map<string, MonthlyAggregate> {
    const monthly = new Map<string, MonthlyAggregate>();

    for (const inv of invoices) {
      const month = this.toIsoMonth(inv.issuedDate);
      if (!month) continue;

      // Calculate payment ratio: for PAID = 100%, for PARTIAL = amountPaid/totalAmount
      let paymentRatio = 0;
      if (inv.status === InvoiceStatus.PAID) {
        paymentRatio = 1;
      } else if (inv.totalAmount > 0) {
        paymentRatio = (inv.amountPaid ?? 0) / inv.totalAmount;
      } else {
        paymentRatio = 0;
      }

      // Skip if no payment (edge case)
      if (paymentRatio <= 0) continue;

      let monthRevenue = 0;
      let monthCogs = 0;
      let monthUnits = 0;

      for (const line of inv.lineItems ?? []) {
        const lineRevenue =
          (line.amount ?? line.quantity * line.unitPrice) * paymentRatio;
        const unitCost =
          productCostMap.get(line.productId?.toString() ?? '') ?? 0;
        const lineCogs = line.quantity * unitCost * paymentRatio;

        monthRevenue += lineRevenue;
        monthCogs += lineCogs;
        monthUnits += line.quantity * paymentRatio;
      }

      // Fallback: if no line items, use totalAmount * paymentRatio
      if ((!inv.lineItems || inv.lineItems.length === 0) && inv.totalAmount) {
        monthRevenue += inv.totalAmount * paymentRatio;
      }

      const existing = monthly.get(month) ?? {
        revenue: 0,
        cogs: 0,
        grossProfit: 0,
        unitsSold: 0,
      };

      monthly.set(month, {
        revenue: Math.round((existing.revenue + monthRevenue) * 100) / 100,
        cogs: Math.round((existing.cogs + monthCogs) * 100) / 100,
        grossProfit: 0, // computed below
        unitsSold: existing.unitsSold + monthUnits,
      });
    }

    // Compute gross profit per month
    for (const [month, data] of monthly) {
      monthly.set(month, {
        ...data,
        grossProfit: Math.round((data.revenue - data.cogs) * 100) / 100,
      });
    }

    return monthly;
  }

  private toIsoMonth(date: Date): string | undefined {
    if (!date) return undefined;
    const d = date instanceof Date ? date : new Date(date);
    if (Number.isNaN(d.getTime())) return undefined;
    const year = d.getFullYear();
    const month = d.getMonth() + 1;
    return `${year}-${String(month).padStart(2, '0')}`;
  }

  // ─── Forecasting ────────────────────────────────────────────────────────────

  /**
   * Forecast a single metric's future values from its historical monthly data.
   * Returns predicted data points that EXTEND the timeline (never overwrite history).
   */
  async forecastMetric(
    historical: MonthlyDataPointDto[],
    horizonMonths: number
  ): Promise<MonthlyDataPointDto[]> {
    if (historical.length === 0 || horizonMonths <= 0) {
      return [];
    }

    const values = historical.map((p) => p.value);
    const lastDate = historical.at(-1)?.date ?? historical[0].date;

    let predictedValues: number[];

    if (values.length >= MIN_DATA_POINTS) {
      predictedValues = await this.tfPredict(values, horizonMonths);
    } else {
      this.logger.warn(
        `Insufficient data (${values.length} points) for TF model, using linear extrapolation`
      );
      predictedValues = this.linearExtrapolation(values, horizonMonths);
    }

    return predictedValues.map((value, i) => ({
      date: this.addMonths(lastDate, i + 1),
      value: Math.max(0, Math.round(value * 100) / 100),
    }));
  }

  // ─── TensorFlow Model ──────────────────────────────────────────────────────

  /**
   * Train a dense neural network on sliding windows of historical data,
   * then predict future values autoregressively.
   */
  private async tfPredict(
    values: number[],
    horizonMonths: number
  ): Promise<number[]> {
    const minVal = Math.min(...values);
    const maxVal = Math.max(...values);
    const range = maxVal - minVal || 1;

    const normalized = values.map((v) => (v - minVal) / range);

    const { xs, ys } = this.buildWindows(normalized);

    if (xs.length === 0) {
      return this.linearExtrapolation(values, horizonMonths);
    }

    const xsTensor = tf.tensor2d(xs);
    const ysTensor = tf.tensor2d(ys, [ys.length, 1]);

    const model = this.buildModel(WINDOW_SIZE);

    await model.fit(xsTensor, ysTensor, {
      epochs: TRAINING_EPOCHS,
      batchSize: Math.min(32, xs.length),
      shuffle: true,
      verbose: 0,
    });

    // Autoregressive prediction
    const predictions: number[] = [];
    let window = normalized.slice(-WINDOW_SIZE);

    for (let i = 0; i < horizonMonths; i++) {
      const input = tf.tensor2d([window]);
      const output = model.predict(input) as tf.Tensor;
      const [predNorm] = await output.data();
      const predDenorm = predNorm * range + minVal;

      predictions.push(predDenorm);
      window = [...window.slice(1), predNorm];

      tf.dispose([input, output]);
    }

    tf.dispose([xsTensor, ysTensor]);
    model.dispose();

    return predictions;
  }

  private buildWindows(normalized: number[]): { xs: number[][]; ys: number[] } {
    const xs: number[][] = [];
    const ys: number[] = [];

    for (let i = 0; i <= normalized.length - WINDOW_SIZE - 1; i++) {
      xs.push(normalized.slice(i, i + WINDOW_SIZE));
      ys.push(normalized[i + WINDOW_SIZE]);
    }

    return { xs, ys };
  }

  private buildModel(inputSize: number): tf.LayersModel {
    const model = tf.sequential();

    model.add(
      tf.layers.dense({
        inputShape: [inputSize],
        units: 16,
        activation: 'relu',
      })
    );

    model.add(
      tf.layers.dense({
        units: 8,
        activation: 'relu',
      })
    );

    model.add(
      tf.layers.dense({
        units: 1,
      })
    );

    model.compile({
      optimizer: tf.train.adam(LEARNING_RATE),
      loss: 'meanSquaredError',
    });

    return model;
  }

  // ─── Fallback: Linear Extrapolation ────────────────────────────────────────

  private linearExtrapolation(values: number[], steps: number): number[] {
    if (values.length < 2) {
      const last = values[0] ?? 0;
      return Array.from({ length: steps }, () => last);
    }

    const recent = values.slice(-Math.min(6, values.length));
    const n = recent.length;

    let sumX = 0;
    let sumY = 0;
    let sumXY = 0;
    let sumX2 = 0;

    for (let i = 0; i < n; i++) {
      sumX += i;
      sumY += recent[i];
      sumXY += i * recent[i];
      sumX2 += i * i;
    }

    const denominator = n * sumX2 - sumX * sumX;
    const slope =
      denominator === 0 ? 0 : (n * sumXY - sumX * sumY) / denominator;
    const intercept = (sumY - slope * sumX) / n;

    const predictions: number[] = [];
    for (let i = 0; i < steps; i++) {
      predictions.push(intercept + slope * (n + i));
    }

    return predictions;
  }

  // ─── Date Helpers ──────────────────────────────────────────────────────────

  private addMonths(isoMonth: string, months: number): string {
    const [yearStr, monthStr] = isoMonth.split('-');
    const year = Number.parseInt(yearStr, 10);
    const month = Number.parseInt(monthStr, 10);

    const totalMonths = (year - 1) * 12 + month + months - 1;
    const newYear = Math.floor(totalMonths / 12) + 1;
    const newMonth = (totalMonths % 12) + 1;

    return `${newYear}-${String(newMonth).padStart(2, '0')}`;
  }
}
