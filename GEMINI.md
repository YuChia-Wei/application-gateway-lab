# Project Overview

This project is an application gateway built with .NET and YARP (Yet Another Reverse Proxy). It serves as a central entry point for routing traffic to backend services. The solution includes the main application gateway, a sample Web API, and a sample Angular web application.

The key technologies used are:

*   **.NET (C#):** The core technology for the application gateway and the sample API.
*   **YARP (Yet Another Reverse Proxy):** For handling reverse proxying of requests to backend services.
*   **Angular:** The framework for the sample web application.
*   **OpenID Connect (OIDC):** For authentication against an identity provider like Keycloak.
*   **Redis:** Used for session and data protection storage.
*   **Docker:** Used to run dependencies like Redis and Keycloak.
*   **Helm:** For packaging and deploying the application to Kubernetes.

# Building and Running

## Dependencies

Before running the project, you need to have the following dependencies running:

*   **Redis:**
    ```bash
    docker run -d -p 6379:6379 --name local-redis redis
    ```
*   **Keycloak:**
    ```bash
    docker run -d -p 8080:8080 -p 8443:8443 \
        -e KEYCLOAK_ADMIN=user \
        -e KEYCLOAK_ADMIN_PASSWORD=password \
        quay.io/keycloak/keycloak start-dev
    ```
    You will also need to import the test client configuration from `keycloak/test_client.json`.

## Running the Application

To run the application, you need to start all three projects (`application_gateway_lab`, `Sample.WebApi`, and `Sample.Web`) simultaneously.

1.  **Backend (C# Projects):**
    Open the `src/app-gateway-lab.sln` solution in Visual Studio or your preferred IDE. You will need to configure the solution to launch both `application_gateway_lab` and `Sample.WebApi` projects upon startup.

    Alternatively, you can run the projects from the command line:

    ```bash
    # Run the Application Gateway
    dotnet run --project src/application_gateway_lab/application_gateway_lab.csproj

    # Run the Sample API
    dotnet run --project src/Sample.Api/Sample.WebApi.csproj
    ```

2.  **Frontend (Angular Project):**
    Navigate to the `src/Sample.Web` directory and run the following commands:

    ```bash
    npm install
    npm start
    ```

# Development Conventions

*   The project uses a standard .NET solution structure.
*   The backend projects follow the standard C# and ASP.NET Core conventions.
*   The frontend project follows the standard Angular CLI project structure.
*   Configuration for the reverse proxy is stored in `ReverseProxy-ClustersSetting.json` and `ReverseProxy-RoutesSetting.json`.
*   The project includes a Helm chart for Kubernetes deployment, located in the `deploy/helm` directory.
