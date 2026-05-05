import {
  IsArray,
  ArrayMinSize,
  ArrayMaxSize,
  IsMongoId,
  ArrayUnique,
} from 'class-validator';

export const BULK_DELETE_MAX_IDS = 100;

export class BulkDeleteProductsDto {
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(BULK_DELETE_MAX_IDS)
  @IsMongoId({ each: true })
  @ArrayUnique()
  ids: string[];
}

export interface BulkDeleteProductsResponse {
  deleted: number;
  notFound: string[];
}
