FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ImageReport/ImageReport.csproj ImageReport/
RUN dotnet restore ImageReport/ImageReport.csproj
COPY ImageReport/ ImageReport/
RUN dotnet publish ImageReport/ImageReport.csproj -c Release -o /app/publish --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "ImageReport.dll"]
