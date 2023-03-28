/**
 * Tagged template generating a biscuit builder from datalog code
 *
 * @param {string[]} strings
 * @param {any[]} values
 */
export function biscuit(strings: string[], ...values: any[]): BiscuitBuilder;
/**
 * Tagged template generating a block builder from datalog code
 *
 * @param {string[]} strings
 * @param {any[]} values
 */
export function block(strings: string[], ...values: any[]): BlockBuilder;
/**
 * Tagged template generating an authorizer from datalog code
 *
 * @param {string[]} strings
 * @param {any[]} values
 */
export function authorizer(strings: string[], ...values: any[]): Authorizer;
/**
 * Tagged template generating a fact from datalog code
 *
 * @param {string[]} strings
 * @param {any[]} values
 */
export function fact(strings: string[], ...values: any[]): Fact;
/**
 * Tagged template generating a rule from datalog code
 *
 * @param {string[]} strings
 * @param {any[]} values
 */
export function rule(strings: string[], ...values: any[]): Rule;
/**
 * Tagged template generating a check from datalog code
 *
 * @param {string[]} strings
 * @param {any[]} values
 */
export function check(strings: string[], ...values: any[]): Check;
/**
 * Tagged template generating a policy from datalog code
 *
 * @param {string[]} strings
 * @param {any[]} values
 */
export function policy(strings: string[], ...values: any[]): Policy;
/**
 * Adapt JS values so they can be deserialized as terms by the wasm
 * module.
 *
 * @param {any} value
 */
export function prepareTerm(value: any): any;
