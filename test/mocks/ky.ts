class HTTPError extends Error {
  response: { status: number; headers: Map<string, string> };

  constructor(status = 500) {
    super('HTTPError');
    this.name = 'HTTPError';
    this.response = {
      status,
      headers: new Map<string, string>(),
    };
  }
}

const httpClient = {
  get: () => Promise.resolve({ json: () => Promise.resolve({}) }),
  post: () => Promise.resolve({ json: () => Promise.resolve({}) }),
  put: () => Promise.resolve({ json: () => Promise.resolve({}) }),
  patch: () => Promise.resolve({ json: () => Promise.resolve({}) }),
  delete: () => Promise.resolve({ json: () => Promise.resolve({}) }),
};

const ky = {
  create: () => httpClient,
};

export { HTTPError };
export default ky;
