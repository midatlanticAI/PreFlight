---
title: Vector and embedding weaknesses
slug: vector-embedding-weaknesses
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Vector Embedding Weaknesses
  - RAG Ingestion
sources:
  - title: 'OWASP LLM08 — Vector and Embedding Weaknesses'
    url: https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/
  - title: 'CWE-200 — Exposure of Sensitive Information'
    url: https://cwe.mitre.org/data/definitions/200.html
  - title: 'Pinecone — Namespaces'
    url: https://docs.pinecone.io/guides/indexes/use-namespaces
  - title: 'Weaviate — Multi-tenancy'
    url: https://weaviate.io/developers/weaviate/concepts/data#multi-tenancy
summary: A vector similarity search without a tenant / user / org filter returns the global nearest neighbors. Tenant A asks "what was discussed in last week's meeting" and the top-K includes tenant B's confidential notes. Pin the query to the calling scope, always.
---

## What this is

A vector store is a database. Like every other database, access control is a property the developer configures; the default is "the query returns matches based on similarity, regardless of who owns the documents." For RAG systems with multiple users / tenants / orgs / projects, that default leaks across boundaries.

```ts
// Cross-tenant leak waiting to happen.
const results = await pinecone.query({
  vector: await embed(userQuery),
  topK: 5,
  // No namespace. No filter. Searches everything.
});
return Response.json({ results });
```

Three users upload documents. Each user's documents go into the same index without scoping. User 1 asks "what's in the Acme Q3 report" and the top-5 nearest neighbors include chunks from User 2's "Globex Q3 strategy" because the embeddings are semantically close. User 1 sees data they should never have access to.

## Why it matters

The pattern shows up in two specific failure modes:

**Cross-tenant retrieval leakage.** Documents from different tenants are stored in the same index without separation. Similarity search returns matches across tenants based on semantic closeness, not access rights. The LLM treats the retrieved chunks as authoritative context and surfaces the cross-tenant content to the calling user.

**Embedding-cache poisoning.** Caches keyed by user input (without normalization) can be poisoned: an attacker submits a crafted query that causes the cache to store an attacker-controlled embedding under a key a different user will later hit. The next user's query hits the poisoned cache entry and gets the attacker's nearest-neighbors.

OWASP LLM08 covers both as the vector-and-embedding-weakness family. The blast radius scales with the index's diversity. A single-tenant RAG has nothing to leak; a 1,000-tenant SaaS RAG has 1,000 ways to leak.

## What the failure looks like

Pre-Flight scans for vector-store similarity queries (`pinecone.query`, `weaviate.search`, `qdrant.search`, `chroma.query`, `milvus.search`, `pgvector` queries, `vectorStore.similaritySearch`, generic `.topK`) where the surrounding code contains neither:

- A namespace, filter, where-clause, or tenant/org/user-ID reference in the query.
- A user-context variable indicating the caller's scope.

If neither is present, the query runs against the global index and the finding fires.

## What the fix looks like

Two motions, often combined.

**1. Use the vector store's namespace primitive.** Every modern vector store has a tenant-isolation concept. Use it.

```ts
// Pinecone
await pinecone.upsert({
  namespace: tenantId,  // one namespace per tenant
  vectors: [...],
});
const results = await pinecone.query({
  namespace: tenantId,
  vector: queryEmbedding,
  topK: 5,
});

// Weaviate (multi-tenancy mode)
const result = await client.collections
  .get('Document')
  .withTenant(tenantId)
  .query.nearVector(queryEmbedding, { limit: 5 });

// Qdrant (collections per tenant, OR filter)
const result = await client.search('documents', {
  vector: queryEmbedding,
  filter: { must: [{ key: 'tenantId', match: { value: tenantId } }] },
  limit: 5,
});

// pgvector (Postgres RLS or explicit WHERE)
const rows = await db.query(
  `SELECT * FROM documents WHERE tenant_id = $1
   ORDER BY embedding <-> $2 LIMIT 5`,
  [tenantId, queryEmbedding]
);
```

The namespace becomes part of the storage key. Cross-namespace queries are impossible without explicitly opening a different namespace.

**2. Layer access metadata onto chunks and filter at query time.**

For finer-grained access control (e.g., a user belongs to multiple orgs, or documents have access lists), attach metadata at ingestion and filter at query.

```ts
// At ingestion
await pinecone.upsert({
  namespace: tenantId,
  vectors: [{
    id: chunkId,
    values: embedding,
    metadata: {
      ownerId: userId,
      visibility: 'org' | 'team' | 'private',
      allowedUserIds: [...],
      uploadedAt: Date.now(),
    },
  }],
});

// At query
const allowedScopes = await resolveAllowedScopes(currentUser);
const results = await pinecone.query({
  namespace: tenantId,
  vector: queryEmbedding,
  filter: {
    $or: [
      { visibility: 'org' },
      { allowedUserIds: { $in: [currentUser.id] } },
      { ownerId: currentUser.id },
    ],
  },
  topK: 5,
});
```

The query now returns only chunks the calling user is entitled to see. Even within the namespace, access control narrows the result set.

## Embedding cache discipline

If you cache embeddings to save on API calls, key the cache by `(content_hash, model, version)`, not by user input. User input is attacker-controllable; the hash of normalized content is not.

```ts
import { createHash } from 'node:crypto';

function cacheKey(content: string, model: string): string {
  // Normalize first (NFC unicode, trim whitespace, lowercase if the model is case-insensitive)
  const normalized = content.normalize('NFC').trim();
  const hash = createHash('sha256').update(normalized).digest('hex');
  return `embed:${model}:${hash}`;
}
```

Two users submitting the same content get the same cache hit. Different inputs get different keys. An attacker can't poison "what's the company strategy" because they don't control the hash of the user's actual query.

## Related

- [RAG ingestion](/learn/patterns/rag-ingestion) covers the ingestion-side companion failure.
- [LLM security](/learn/patterns/llm-security) covers the broader OWASP LLM Top 10 picture.
- [Supabase RLS](/learn/patterns/supabase-rls) covers the same multi-tenant discipline applied at the relational-DB layer.

## Sources

OWASP LLM08 is the authoritative reference. Pinecone, Weaviate, Qdrant, and Chroma all publish multi-tenancy guides at the URLs above. CWE-200 names the broader information-exposure class this pattern fits inside.
