# Pull base image
FROM python:3.7.14

# Set environment varibles
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Get the pre-requisites
# 1. g++ and libc-dev needed to compile unixodbc-dev 
# 2. curl which is needed to download SQL Server driver
RUN apt-get update && apt-get install -y g++ libc-dev 

#RUN apt-get update 
RUN . ~/.bashrc

# Part 2. Get unixodbc-dev
RUN apt-get install -y unixodbc-dev


# Initialize the base folders..
# WORKDIR /VaultModule/
# RUN ls -l
# COPY ./  /VaultModule/
# RUN ls -l
WORKDIR /usr/app/src
COPY main.py ./

# Install the library's dependencies and the library itself..
# WORKDIR 
RUN pip install -r requirements.txt
#RUN pip install .

# Done, ready to execute
CMD ["python", "./main.py"]
