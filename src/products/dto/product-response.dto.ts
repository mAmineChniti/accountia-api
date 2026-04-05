export class ProductResponseDto {
  id!: string;
  businessId!: string;
  name!: string;
  description!: string;
  unitPrice!: number;
  cost!: number;
  quantity!: number;
  currency!: string;
  createdAt!: Date;
  updatedAt!: Date;
}

export class ProductListResponseDto {
  products!: ProductResponseDto[];
  total!: number;
  page!: number;
  limit!: number;
  totalPages!: number;
}
