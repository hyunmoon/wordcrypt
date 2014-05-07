---
title: Review of a very awesome project
tag: very_awesome_project
---
## Usage

The
[very awesome project](https://github.com/joehacker/very_awesome_project)
was very awesome to use. The `README` provided clear instructions to
get started, after cloning the project I just ran:

    $ make
    $ ./very_awesome

and was good to go!

## Style

The code was well organized, there was a very clean separation between
the `widget` module and the `sprocket` module. However, the `foo` module could have been better organized:

- refactor the `bar` functionality out into a separate module
- use a more consistent naming scheme, for example, the foo getter is named `get_foo` but the setter is `fooSet`

## Philosophy

Dennis Ritchie would be proud, this project was very Unixy.

- it exhibited a strong single center: the `foo` algorithm was the
  core of the program while the `widget` and `sprocket` modules
  provided a thin interface wrapper to the algorithm
- the output of the program was clean and simple, suitable for use in
  a pipeline

However, there is still room for improvement:

- Changing the `-s` flag to `-f` would be more consistent with other
  command line utilities ([Rule of Least Surprise](http://www.catb.org/esr/writings/taoup/html/ch01s06.html#id2878339))
- There is no error checking on the return of `get_foo`. If this call
  fails, it may cause unexpected and hard-to-debug behavior. Check for
  all error conditions and print a message to /standard error/ and
  exit immediately if it doesn't make sense to continue
  ([Rule of Repair](http://www.catb.org/esr/writings/taoup/html/ch01s06.html#id2878538))
