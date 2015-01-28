# CONTRIBUTING

## The Development Philosophy

Blimey is developed under the MIT license, which means it's Open Source and that we're accepting contributions to the project.

If you're thinking about contributing to blimey, this page is the place to start.

We try to build blimey as a robust piece of software, with a simple and elegant design. To try and achieve this we apply the principles of emergent design, and expect contributions to do so as well.

Quoting "The RSpec Book":

> "BDD calls Test-Driven Development coding by example, which places emphasis on using examples to drive out the behaviour of the code. The fact that these examples become tests once the code is written is a secondary concern"

So, what does this mean in the context of blimey?
It means that we couldn't care less about "code coverage" or writing tests for the sake of doing it.
It means that we write examples of how we imagine our code will be used, before writing our code, and then we write the minimum amount of code to make the expectations of those examples to pass.
It means that we don't do a lot of upfront design, instead, we let it emerge as a response to our examples.

The consequences of this are often: small, simple and clean methods and classes. Responsibility separation in methods and classes. Injection of dependencies. And a number of other advantages that become clear as the software progresses.

## Tools

Blimey is developed in **Python 3**. We try to keep the number of dependencies low, not always with great success. To check the dependecies used by Blimey, see the `requirements.txt` file.

To install nose you'll need to run pip. Depending on your setup, you pip executable might be called pip or pip3:

`pip3 install nose`

For the remaining tools, you can take advantage of the requirements.txt contained in the repository:

`pip3 install -r requirements.txt --use-mirrors`

## Running the examples

To run the examples you'll just need to run the script provided in bin/tests. From the root of the project execute the following:

`bin/tests`

This will run nosetests and pep8 with the appropriate parameters.

## Writing a feature

Here's a guide for how to develop a feature following the development philosophy described above.
Let's imagine we're writing a class called *LightBulb* inside the *blimey* package:

- Create a file called `spec/blimey/light_bulb_spec.py`
- Import the (still inexistent) class you're going to write:

```python
from blimey.light_bulb import LightBulb
```

- Inside that file, create a class called *LightBulbSpec*
- Create the first example, describing one behaviour of your class, start with the word "it". Let's say *it_should_be_lit_after_being_turned_on* which shoud look something like this:

```python
from nose.tools import *
from blimey.light_bulb import LightBulb


class LightBulbSpec:
    def it_should_be_lit_after_being_turned_on(self):
        bulb = LightBulb()
        bulb.turn_on()

        eq_(bulb.turned_on(), True)

```
- Run `bin/tests`
- Fix any code styling issues that it may report
- At this point you should get the following error `ImportError: No module named 'blimey.light_bulb'`. Fix it by creating the file `blimey/light_bulb.py`.
- Run `bin/tests` again. You should now get the error `ImportError: cannot import name LightBulb`.
- Create the *LightBulb* class inside the `blimey.light_bulb`. At this point your class should have nothing else other then a *pass* statement.

```python
class LightBulb:
    pass

```
- Run `bin/tests` again. The error should now be `AttributeError: 'LightBulb' object has no attribute 'turn_on'`. So let's create it.

```python
class LightBulb:

    def turn_on(self):
        pass

```
- Once more run `bin/tests`. You should be getting the hang of this now, we're letting our example lead what we do. It's important not to write more than what our example is leading us to do, otherwise our design won't emerge from our idealised example. Now you should get this error `AttributeError: 'LightBulb' object has no attribute 'turned_on'`, so let's write our turned_on method.

```python
class LightBulb:

    def turn_on(self):
        pass

    def turned_on(self):
        return True

```
- Run `bin/tests` and all our tests should now pass. But..., our LightBulb class doesn't seem all that useful. turned_on always return *True*. What's up with that? Well, that's all we need it to do for now, but our light bulb does more that just stay lit. So, let's describe another behaviour. Let's say, `it_should_not_lit_before_being_turned_on`.

```python
from nose.tools import *
from blimey.light_bulb import LightBulb


class LightBulbSpec:
    def it_should_be_lit_after_being_turned_on(self):
        bulb = LightBulb()
        bulb.turn_on()

        eq_(bulb.turned_on(), True)

    def it_should_not_lit_before_being_turned_on(self):
        bulb = LightBulb()
        eq_(bulb.turned_on(), False)

```
- Now our `it should not lit before being turned on` test is failling with the following error `AssertionError: True != False`. Ok, so our example is telling us to change our behaviour, so let's do it. Although we could do this in one step, for clarity sake let's do it in two:

```python
class LightBulb:
    def __init__(self):
        self._on = False

    def turn_on(self):
        pass

    def turned_on(self):
        return self._on

```
- We fixed our test, but we broke `it should be lit after being turned on`. This is our example driving us to change our incorrect implementation. In response to this we fix the turn_on method:

```python
class LightBulb:
    def __init__(self):
        self._on = False

    def turn_on(self):
        self._on = True

    def turned_on(self):
        return self._on

```

This should drive our implementation to be simple and make our interface a result of what we wish we had, producing better and clear code.
In this example refactoring is not needed due to it's extreme simplicity, but **every time you get green, stop, look at both your code and your tests, and search for possible ways of improving it without changing or adding functionality**. Rename methods and properties which have names that are not explicit enough, remove complexity, generally clean your code. Do only one change at a time and alway run the tests after making the change. This step is vital to achieve the goals to which this methodology aspires.

## Making pull requests

Before making a pull request, be sure to run nose and pep8, using the bin/tests script, to ensure that your code is ready to be merged.
Both specs and code should follow the pep8 standards.

To make this easier, we provide a git_hooks folder that contains a pre-commit hook, that will do the work for you. Just copy it to your repository git hooks folder. From the base folder of your repository do:

`cp ./git_hooks/pre_commit .git/hooks`
