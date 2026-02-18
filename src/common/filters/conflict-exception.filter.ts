import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  ConflictException,
} from '@nestjs/common';
import { Response } from 'express';

@Catch(ConflictException)
export class ConflictExceptionFilter implements ExceptionFilter {
  catch(exception: ConflictException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const exceptionResponse = exception.getResponse();

    if (
      typeof exceptionResponse === 'object' &&
      exceptionResponse !== null &&
      'type' in exceptionResponse
    ) {
      response.status(409).json(exceptionResponse);
      return;
    }

    response.status(409).json({
      statusCode: 409,
      message: exception.message,
      timestamp: new Date().toISOString(),
    });
  }
}
