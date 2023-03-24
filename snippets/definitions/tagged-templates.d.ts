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
