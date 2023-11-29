# AWS Permission manager

CLI app to help with the management of AWS groups, permission sets and accounts

The idea is that each 'job function' is assigned a definition file that contains:

- which accounts people that do that job need access to
- the permissions they need in those accounts

So that access can be granted in a way that abstracts account by account permissions

## Prerequisites

An AWS account with identity center configured

## Running

This is still pretty rough...

1. Create a `.env` file and set two values in the file:

  ```env
  export IDENTITY_CENTER_ARN="your identity center ARN"
  export IDENTITY_STORE_ID="your identity store ID"
  ```

1. Source the `.env` file to set the values `source .env`

1. Set up a virtual environment
  
  ```console
  python -m env .venv
  ```

1. Source the virtual environment

  ```console
  source .venv/bin/activate
  ```

1. Install the things

  ```console
  pip install --upgrade pip -r requirements_dev.txt -e src
  ```

1. Create a `job_definitions` directory

  Use the `job_definitions_sample` as a guide on what a job function file should look like

1. Run the thing

  ```console
  apm
  ```
  