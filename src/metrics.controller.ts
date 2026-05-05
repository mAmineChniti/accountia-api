import { Controller, Get, Res } from '@nestjs/common';
import type { Response } from 'express';
import * as client from 'prom-client';

import { ApiTags, ApiOkResponse } from '@nestjs/swagger';

@ApiTags('metrics')
@Controller('metrics')
export class MetricsController {
  constructor() {
    // Collecte les métriques par défaut (CPU, Mémoire, etc.)
    if (
      client.register.getSingleMetric('process_cpu_seconds_total') === undefined
    ) {
      client.collectDefaultMetrics();
    }
  }

  @Get()
  @ApiOkResponse({ type: String, description: 'Prometheus metrics' })
  async getMetrics(@Res() res: Response) {
    res.set('Content-Type', client.register.contentType);
    const metrics = await client.register.metrics();
    res.end(metrics);
  }
}
