/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as http from "../http.js";
import type * as lib_securityLogger from "../lib/securityLogger.js";
import type * as paymentAttemptTypes from "../paymentAttemptTypes.js";
import type * as paymentAttempts from "../paymentAttempts.js";
import type * as scanner_collectionPipeline from "../scanner/collectionPipeline.js";
import type * as scanner_discovery from "../scanner/discovery.js";
import type * as scanner_pipeline from "../scanner/pipeline.js";
import type * as scanner_queries from "../scanner/queries.js";
import type * as scanner_scanners_aiFirstReview from "../scanner/scanners/aiFirstReview.js";
import type * as scanner_scanners_codePatterns from "../scanner/scanners/codePatterns.js";
import type * as scanner_scanners_crossPlatform from "../scanner/scanners/crossPlatform.js";
import type * as scanner_scanners_domainSafelist from "../scanner/scanners/domainSafelist.js";
import type * as scanner_scanners_externalLinks from "../scanner/scanners/externalLinks.js";
import type * as scanner_scanners_frameworkContext from "../scanner/scanners/frameworkContext.js";
import type * as scanner_scanners_hardStops from "../scanner/scanners/hardStops.js";
import type * as scanner_scanners_index from "../scanner/scanners/index.js";
import type * as scanner_scanners_preFilter from "../scanner/scanners/preFilter.js";
import type * as scanner_scanners_reviewDocs_codeAnalysis from "../scanner/scanners/reviewDocs/codeAnalysis.js";
import type * as scanner_scanners_reviewDocs_codeInjection from "../scanner/scanners/reviewDocs/codeInjection.js";
import type * as scanner_scanners_reviewDocs_credentialAccess from "../scanner/scanners/reviewDocs/credentialAccess.js";
import type * as scanner_scanners_reviewDocs_dangerousOperations from "../scanner/scanners/reviewDocs/dangerousOperations.js";
import type * as scanner_scanners_reviewDocs_dataExfiltration from "../scanner/scanners/reviewDocs/dataExfiltration.js";
import type * as scanner_scanners_reviewDocs_excessiveAgency from "../scanner/scanners/reviewDocs/excessiveAgency.js";
import type * as scanner_scanners_reviewDocs_index from "../scanner/scanners/reviewDocs/index.js";
import type * as scanner_scanners_reviewDocs_memoryPoisoning from "../scanner/scanners/reviewDocs/memoryPoisoning.js";
import type * as scanner_scanners_reviewDocs_obfuscation from "../scanner/scanners/reviewDocs/obfuscation.js";
import type * as scanner_scanners_reviewDocs_promptInjection from "../scanner/scanners/reviewDocs/promptInjection.js";
import type * as scanner_scanners_reviewDocs_socialEngineering from "../scanner/scanners/reviewDocs/socialEngineering.js";
import type * as scanner_scanners_reviewDocs_supplyChain from "../scanner/scanners/reviewDocs/supplyChain.js";
import type * as scanner_scanners_reviewDocs_untrustedContent from "../scanner/scanners/reviewDocs/untrustedContent.js";
import type * as scanner_scanners_standardCompliance from "../scanner/scanners/standardCompliance.js";
import type * as scanner_scanners_types from "../scanner/scanners/types.js";
import type * as scanner_store from "../scanner/store.js";
import type * as scanner_submit from "../scanner/submit.js";
import type * as security from "../security.js";
import type * as seedSecurityEvents from "../seedSecurityEvents.js";
import type * as users from "../users.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";

declare const fullApi: ApiFromModules<{
  http: typeof http;
  "lib/securityLogger": typeof lib_securityLogger;
  paymentAttemptTypes: typeof paymentAttemptTypes;
  paymentAttempts: typeof paymentAttempts;
  "scanner/collectionPipeline": typeof scanner_collectionPipeline;
  "scanner/discovery": typeof scanner_discovery;
  "scanner/pipeline": typeof scanner_pipeline;
  "scanner/queries": typeof scanner_queries;
  "scanner/scanners/aiFirstReview": typeof scanner_scanners_aiFirstReview;
  "scanner/scanners/codePatterns": typeof scanner_scanners_codePatterns;
  "scanner/scanners/crossPlatform": typeof scanner_scanners_crossPlatform;
  "scanner/scanners/domainSafelist": typeof scanner_scanners_domainSafelist;
  "scanner/scanners/externalLinks": typeof scanner_scanners_externalLinks;
  "scanner/scanners/frameworkContext": typeof scanner_scanners_frameworkContext;
  "scanner/scanners/hardStops": typeof scanner_scanners_hardStops;
  "scanner/scanners/index": typeof scanner_scanners_index;
  "scanner/scanners/preFilter": typeof scanner_scanners_preFilter;
  "scanner/scanners/reviewDocs/codeAnalysis": typeof scanner_scanners_reviewDocs_codeAnalysis;
  "scanner/scanners/reviewDocs/codeInjection": typeof scanner_scanners_reviewDocs_codeInjection;
  "scanner/scanners/reviewDocs/credentialAccess": typeof scanner_scanners_reviewDocs_credentialAccess;
  "scanner/scanners/reviewDocs/dangerousOperations": typeof scanner_scanners_reviewDocs_dangerousOperations;
  "scanner/scanners/reviewDocs/dataExfiltration": typeof scanner_scanners_reviewDocs_dataExfiltration;
  "scanner/scanners/reviewDocs/excessiveAgency": typeof scanner_scanners_reviewDocs_excessiveAgency;
  "scanner/scanners/reviewDocs/index": typeof scanner_scanners_reviewDocs_index;
  "scanner/scanners/reviewDocs/memoryPoisoning": typeof scanner_scanners_reviewDocs_memoryPoisoning;
  "scanner/scanners/reviewDocs/obfuscation": typeof scanner_scanners_reviewDocs_obfuscation;
  "scanner/scanners/reviewDocs/promptInjection": typeof scanner_scanners_reviewDocs_promptInjection;
  "scanner/scanners/reviewDocs/socialEngineering": typeof scanner_scanners_reviewDocs_socialEngineering;
  "scanner/scanners/reviewDocs/supplyChain": typeof scanner_scanners_reviewDocs_supplyChain;
  "scanner/scanners/reviewDocs/untrustedContent": typeof scanner_scanners_reviewDocs_untrustedContent;
  "scanner/scanners/standardCompliance": typeof scanner_scanners_standardCompliance;
  "scanner/scanners/types": typeof scanner_scanners_types;
  "scanner/store": typeof scanner_store;
  "scanner/submit": typeof scanner_submit;
  security: typeof security;
  seedSecurityEvents: typeof seedSecurityEvents;
  users: typeof users;
}>;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export declare const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
>;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export declare const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
>;

export declare const components: {};
