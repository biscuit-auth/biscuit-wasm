/**
 * Function building an authorizer from a request, or an authorizer directly,
 * when it doesn't depend on the request
 */
export type AuthorizerBuilder = Authorizer | ((req: any) => Authorizer);

/**
 * Phase of the authorization process where the error happened.
 * Extraction is extracting a token string from the HTTP request.
 * Verification is parsing and verifying a token cryptographic integrity.
 * Authorization is making sure the token grants sufficient rights for the request.
 */
export type ErrorType = "extraction" | "verification" | "authorization";

/**
 * Phase of the authorization process where the error happened.
 * Extraction is extracting a token string from the HTTP request.
 * Verification is parsing and verifying a token cryptographic integrity.
 * Authorization is making sure the token grants sufficient rights for the request.
 */
export type BiscuitMiddlewareOptions = {
  /**
   * Public key used to verify the token signatures
   */
  publicKey: PublicKey;
  /**
   * Authorizer policies which will be evaluated before the per-endpoint policies
   */
  priorityAuthorizer: AuthorizerBuilder;
  /**
   * Authorizer policies which will be evaluated after the per-endpoint policies
   */
  fallbackAuthorizer: AuthorizerBuilder;
  /**
   * Custom function for extracting the token string from the request. The default
   * behaviour expects an `Authorization: Bearer` header.
   */
  tokenExtractor: (request: any) => string;
  /**
   * Custom function for parsing and verifying the token. The default behaviour
   * expects a URL-safe-base64-encoded token and will use the provided public
   * key.
   */
  tokenParser: (tokenString: string, publicKey: PublicKey) => Biscuit;

  /**
   * Error handler called when the authorization process fails. The default
   * behaviour logs the error and sends an HTTP error response.
   */
  onError: (
    errorType: ErrorType,
    error: any,
    req: any,
    res: any,
    next: any
  ) => void;
};

export function middleware(
  options: BiscuitMiddlewareOptions
): (
  makeAuthorizer: AuthorizerBuilder
) => (req: any, res: any, next: any) => any;
