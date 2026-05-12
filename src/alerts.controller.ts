import { Body, Controller, HttpCode, Logger, Post } from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';

@ApiTags('alerts')
@Controller('alerts')
export class AlertsController {
  private readonly logger = new Logger(AlertsController.name);

  @Post()
  @HttpCode(200)
  @ApiOkResponse({
    description: 'Alertmanager webhook received',
    schema: {
      example: { received: true },
    },
  })
  receiveAlert(@Body() payload: unknown) {
    this.logger.warn(
      `Alertmanager webhook received: ${JSON.stringify(payload)}`
    );
    return { received: true };
  }
}
