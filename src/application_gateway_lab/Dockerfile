FROM ghcr.io/yuchia-wei/otel-dotnet-auto-instrumentation:10.0-noble-chiseled AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG BuildConfiguration=Debug
WORKDIR /src
COPY ["nuget.config", "."]
COPY ["application-gateway-lab/application-gateway-lab.csproj", "application-gateway-lab/"]
RUN dotnet restore "application-gateway-lab/application-gateway-lab.csproj"
COPY . .
WORKDIR "/src/application-gateway-lab"
RUN dotnet build "application-gateway-lab.csproj" -c $BuildConfiguration -o /app/build

FROM build AS publish
ARG BuildConfiguration=Debug
RUN dotnet publish "application-gateway-lab.csproj" -c $BuildConfiguration -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "application-gateway-lab.dll"]
