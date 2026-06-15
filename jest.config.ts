import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts', '**/*.spec.ts'],
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        tsconfig: 'tsconfig.test.json',
      },
    ],
  },
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html', 'json-summary'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/pro/**/*.ts', // Pro features tested separately
  ],
  coverageThreshold: {
    global: {
      branches: 35,
      functions: 55,
      lines: 58,
      statements: 58,
    },
  },
  // Run tests serially (1 worker) to prevent Node.js heap OOM on machines
  // with limited RAM. ts-jest + large test suites exhaust the V8 heap when
  // multiple Jest workers each load the full module graph simultaneously.
  maxWorkers: 1,
  testTimeout: 30000,
  verbose: true,
  // Show slow tests
  slowTestThreshold: 5000,
};

export default config;


