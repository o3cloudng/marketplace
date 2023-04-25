# Xzeety Africa's Marketplace

Backend Development using Python Django & Django Rest Framework

## Stack 
* Dockerfile & Docker Compose
* Redis
* Celery
* Django
* Django Rest Framework

#

## Guideline/Coding Standard for Django Application
This is an initial thought and serves as a guideline for This Django application.

We will follow [pep8](https://www.python.org/dev/peps/pep-0008/) and [Google python style guideline](https://google.github.io/styleguide/pyguide.html) as standard.

## Naming Convention

* Use meaningful names
* Function and variable names in snake_case
* Classname in PascalCase
* Constants snake_case capitalized
* Indentation/Space

Use 4 spaces for indentation(Python 3 disallows mixing the use of tabs and spaces for indentation)
Separate top level function and classes with two blank lines
Separate method definition inside class by one line
Maximum length of line should be less than 80 characters
There should be no trailing white spaces
Imports
```
Import from Python standard library(1st)
Import from core Django(2nd)
Import from 3rd party vendor(3rd)
Import from Django Apps(4th)(Current Project)
```

Avoid:
```
import *
Migrations
```

Do not modify the files created by makemigration command(do not add custom sql command)

Place custom sql command if needed in a separate file and do not mix it with the auto generated files from makemigration command
Forward and backward migration work only on auto generated files by makemigration command Not all migration can be reversed
```Add — database=<dbConfigName> always in your migration Forward Migration```

```
python manage.py migrate appname 0002 — settings=project.settings.<Env> — database=<dbConfigName>
```

```
python manage.py migrate appname 0003 — settings=project.settings.<Env> — database=<dbConfigName>
```
Suppose it added all the migration 0001.py , 0002.py , 0003.py , 0004.py
Backward Migration

```(Remove New migrations -0002.py , 0003.py , 0004.py)```

```
python manage.py migrate appname 0001 — settings=project.settings.<Env> — database=<dbConfigName>
```
## Response Status

Response message with status codes
```
{
    ‘status’:’success|error’,
    ‘data’:{
             'result':{} || [] , ''
            }, #one level
    ‘meta’:{} #any meta information that you want to pass
}
```
* 200 OK — Success — GET/PUT — return resource/status message
* 201 Created — Success — POST — provide status message or return newly created object
* 204 No Content — Success — DELETE
* 304 Unchanged — Redirect — ALL — Indicates no changes since last request
* 400 Bad Request — Failure — GET/PUT/POST — invalid request, return error messages
* 401 Unauthorized — Failure — ALL — missing credentials/Authentication required
* 403 Forbidden — Failure — ALL — restricted content
* 404 Not Found — Failure — Resource not found
* 405 Method Not Allowed Failure — Failure — ALL — An invalid HTTP method was attempted

#

## App Structure
```
project/
    gitignore
    README.md
    docs/
    requirements/
        local.txt
        qa.txt
        prod.txt
        base.txt
    core/
        settings/
            base.py //copy of original settings.py
            qa.py
            local.py
            prod.py
        urls.py
        wsgi.py
        settings_default.py //renamed settings->settings_default
    app1/
    app2/
        v1/
            api.py // entry point , not much logic
            service.py // all business logic
            util.py // any helper
        test/
        migrations/
        admin.py
        models.py
        apps.py
        urls.py
        views.py
    utils/
        service/
        helper/
Tools/Extra
```

* Code Quality — flake8
* Environment Manager — venv
* Documentation — Swagger
* Testing — pytest
* IDE — sublime,vim,pycharm
* Debug — pdb

References
* [PEP8](https://www.python.org/dev/peps/pep-0008/)
* [Github Style Guide](https://google.github.io/styleguide/pyguide.html)
* [Chromium OS](https://www.chromium.org/chromium-os/)
* [Python Style Guide](python-style-guidelines)
* [PyTest](http://doc.pytest.org/en/latest/)

