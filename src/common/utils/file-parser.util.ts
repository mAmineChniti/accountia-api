import { BadRequestException } from '@nestjs/common';
import * as XLSX from 'xlsx';
import * as csv from 'csv-parse/sync';

/**
 * Parse CSV or Excel file and return array of records
 */
export async function parseFile(
  fileBuffer: Buffer,
  filename: string
): Promise<Record<string, unknown>[]> {
  try {
    const isExcel = filename.endsWith('.xlsx') || filename.endsWith('.xls');

    if (isExcel) {
      return await Promise.resolve(parseExcelFile(fileBuffer));
    } else if (filename.endsWith('.csv')) {
      return await Promise.resolve(parseCSVFile(fileBuffer));
    } else {
      throw new BadRequestException('Only CSV and Excel files are supported');
    }
  } catch (error) {
    if (error instanceof BadRequestException) {
      throw error;
    }
    throw new BadRequestException(
      `Failed to parse file: ${(error as Error).message}`
    );
  }
}

/**
 * Parse Excel file (.xlsx, .xls)
 */
function parseExcelFile(fileBuffer: Buffer): Record<string, unknown>[] {
  const workbook = XLSX.read(fileBuffer, { type: 'buffer' });
  const sheetName = workbook.SheetNames[0];

  if (!sheetName) {
    throw new BadRequestException('Excel file is empty');
  }

  const worksheet = workbook.Sheets[sheetName];
  const records = XLSX.utils.sheet_to_json(worksheet);

  if (!Array.isArray(records) || records.length === 0) {
    throw new BadRequestException('No data found in Excel file');
  }

  return records as Record<string, unknown>[];
}

/**
 * Parse CSV file
 */
function parseCSVFile(fileBuffer: Buffer): Record<string, unknown>[] {
  const csvString = fileBuffer.toString('utf8');
  const records = csv.parse(csvString, {
    columns: true,
    skip_empty_lines: true,
    trim: true,
  });

  if (!Array.isArray(records) || records.length === 0) {
    throw new BadRequestException('No data found in CSV file');
  }

  return records as Record<string, unknown>[];
}
