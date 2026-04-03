export class ProductResponseDto {
  id!: string;
  name!: string;
  description!: string;
  unitPrice!: number;
  quantity!: number;
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
