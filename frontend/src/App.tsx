import { QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { RouterProvider } from "react-router";
import { NonceContext } from "./lib/nonce";
import { createQueryClient } from "./lib/queryClient";
import { createRouter } from "./routes";

// The router root: query client, CSP nonce, and the route table.
export default function App({ nonce }: { nonce: string | undefined }) {
  const [queryClient] = useState(createQueryClient);
  const [router] = useState(createRouter);
  return (
    <NonceContext.Provider value={nonce}>
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>
    </NonceContext.Provider>
  );
}
