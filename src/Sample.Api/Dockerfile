FROM ghcr.io/yuchia-wei/otel-dotnet-auto-instrumentation:10.0-noble-chiseled AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["Sample.Api/Sample.WebApi.csproj", "Sample.Api/"]
RUN dotnet restore "Sample.Api/Sample.WebApi.csproj"
COPY . .
WORKDIR "/src/Sample.Api"
RUN dotnet build "Sample.WebApi.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Sample.WebApi.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Sample.WebApi.dll"]
