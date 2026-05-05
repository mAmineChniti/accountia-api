import { Controller, Get, Res } from "@nestjs/common";
import type { Response } from "express";
import * as promClient from "prom-client";

import { ApiTags, ApiOkResponse } from "@nestjs/swagger";

let defaultMetricsRegistered = false;

@ApiTags("metrics")
@Controller("metrics")
export class MetricsController {
  constructor() {
    // Collect the full default metrics set once for the shared registry.
    if (!defaultMetricsRegistered) {
      promClient.collectDefaultMetrics();
      defaultMetricsRegistered = true;
    }
  }

  @Get()
  @ApiOkResponse({ type: String, description: "Prometheus metrics" })
  async getMetrics(@Res() res: Response) {
    res.set("Content-Type", promClient.register.contentType);
    const metrics = await promClient.register.metrics();
    res.end(metrics);
  }
}
