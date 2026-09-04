export const token = "aWtkcvFe64HXakuc2YUohqIOq8o";
export function authHeader() {
  return { Authorization: "Bearer " + token };
}
