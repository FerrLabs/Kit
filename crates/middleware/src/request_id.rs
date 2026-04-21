//! Request ID propagation — assign a UUID per request, forward to spans
//! and responses for correlation.

// TODO: tower-http SetRequestIdLayer + PropagateRequestIdLayer wrappers
