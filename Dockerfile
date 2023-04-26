# start from an official image
FROM python:3.10.6-alpine

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1


# USER devops
# arbitrary location choice: you can change the directory
RUN mkdir -p /usr/src/app

WORKDIR /usr/src/app


# copy package dependences
COPY Pipfile Pipfile.lock /usr/src/app/


RUN pip install --upgrade pip 

RUN pip install pipenv 

# RUN pipenv --version

# RUN pipenv lock --pre

# install our dependencies
# we use --system flag because we don't need an extra virtualenv
RUN pipenv install --system --deploy

# copy our project code
COPY . /usr/src/app

# RUN pipenv shell
# RUN python manage.py migrate --no-input && python manage.py collectstatic --no-input -v 2
RUN python manage.py collectstatic --no-input -v 2

# expose the port 8000
EXPOSE 8000


RUN adduser -u 5678 --disabled-password --gecos "" appuser && chown -R appuser ./

USER appuser

# define the default command to run when starting the container
CMD ["gunicorn", "--chdir", "core", "--bind", ":8000", "core.wsgi:application", "--reload"]
