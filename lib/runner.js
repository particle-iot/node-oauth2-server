'use strict';

/**
 * Run through the sequence of functions
 *
 * @param {Function[]} fns
 * @param {this} context
 * @param {Function} next
 * @public
 */
function runner(fns, context, next) {
	const last = fns.length - 1;

	function run(pos) {
		fns[pos].call(context, (err) => {
			if (err || pos === last) {
				return next(err);
			}
			run(pos + 1);
		});
	}

	run(0);
}

module.exports = runner;
