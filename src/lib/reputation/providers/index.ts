// src/lib/reputation/providers/index.ts
//
// Registers all live reputation providers at app startup. Importing this
// module has the side effect of calling registerProvider() for each one.
//
// Providers are registered once per process. In Next.js dev mode, module
// state may be re-initialized on hot reload — registerProvider is
// idempotent by name, so re-registration is safe.

import { registerProvider } from "../registry";
import { createUrlhausProvider } from "./urlhaus";

registerProvider(createUrlhausProvider());