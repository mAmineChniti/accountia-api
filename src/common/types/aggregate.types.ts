export interface AggregateResult {
  _id: undefined;
  totalAmount: number;
  count: number;
}

export interface MonthlyAggregateResult {
  _id: {
    year: number;
    month: number;
  };
  total: number;
}
