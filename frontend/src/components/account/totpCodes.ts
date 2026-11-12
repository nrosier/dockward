import { useMutation } from "@tanstack/react-query";
import { ApiError, api } from "../../lib/api";

// 422 validation_failed is the API's answer to a wrong code on a signed-in screen.
export function isWrongCode(error: unknown): boolean {
  return error instanceof ApiError && error.status === 422;
}

// Six digits, as typed. Spaces from a pasted code are dropped.
export function digitsOf(text: string): string {
  return text.replace(/\D/g, "").slice(0, 6);
}

export function useCodeMutation<T>(path: string) {
  return useMutation({ mutationFn: (code: string) => api<T>("POST", path, { code }) });
}
