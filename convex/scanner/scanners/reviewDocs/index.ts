import { REVIEW_DOC as promptInjectionDoc } from "./promptInjection";
import { REVIEW_DOC as credentialAccessDoc } from "./credentialAccess";
import { REVIEW_DOC as dataExfiltrationDoc } from "./dataExfiltration";
import { REVIEW_DOC as codeInjectionDoc } from "./codeInjection";
import { REVIEW_DOC as dangerousOperationsDoc } from "./dangerousOperations";
import { REVIEW_DOC as obfuscationDoc } from "./obfuscation";
import { REVIEW_DOC as memoryPoisoningDoc } from "./memoryPoisoning";
import { REVIEW_DOC as excessiveAgencyDoc } from "./excessiveAgency";
import { REVIEW_DOC as supplyChainDoc } from "./supplyChain";
import { REVIEW_DOC as socialEngineeringDoc } from "./socialEngineering";
import { REVIEW_DOC as codeAnalysisDoc } from "./codeAnalysis";
import { REVIEW_DOC as untrustedContentDoc } from "./untrustedContent";

export const ALL_REVIEW_DOCS = [
  promptInjectionDoc,
  credentialAccessDoc,
  dataExfiltrationDoc,
  codeInjectionDoc,
  dangerousOperationsDoc,
  obfuscationDoc,
  memoryPoisoningDoc,
  excessiveAgencyDoc,
  supplyChainDoc,
  socialEngineeringDoc,
  codeAnalysisDoc,
  untrustedContentDoc,
];

/** Concatenate all review documents into a single prompt section */
export function getReviewDocsPrompt(): string {
  return ALL_REVIEW_DOCS.join("\n\n---\n\n");
}
