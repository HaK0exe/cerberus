// Unit test fixture: mock bearer token used by the auth middleware tests
const mockToken = "eyJhbGciOiJIUzI1NiJ9.eyJtb2NrIjp0cnVlLCJpZCI61fQ.notARealSignatureExample";
test("rejects an expired mock token", () => {
  expect(isExpired(mockToken)).toBe(true);
});
