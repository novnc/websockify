
/**
 * A decorator that will wrap a function or a class. In the case of a non-class
 * function, the wrapped function will behave exactly the same as before.
 * In the case of a class, the wrapper will allow instantiating the function]
 * without using the |new| keyword. This is useful when you don't know
 * ahead of time if the function you will be calling is a class or a non-class
 * function
 *
 * @param  {function} function_or_class
 */
exports.factorify = function factorify(function_or_class) {
    return (...args) => {
        try {
            return function_or_class(...args);
        } catch (e) {
            if (e instanceof TypeError) {
                return new function_or_class(...args);
            } else {
                throw e;
            }
        }
    }
}
