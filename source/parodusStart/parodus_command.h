#ifndef PARODUS_COMMAND_H
#define PARODUS_COMMAND_H

typedef struct
{
    const char *modelName;
    const char *serialNumber;
    const char *manufacturer;
    const char *lastRebootReason;
    const char *firmwareVersion;
    unsigned int bootTime;
    const char *deviceMac;
    const char *webpaInterface;
    const char *webpaUrl;
    int webpaPingTime;
    const char *parodusUrl;
    const char *partnerId;
    const char *seshatUrl;
    const char *clientCertPath;
    const char *sslEngine;
    const char *sslCertType;
    const char *sslReferenceName;
    const char *tokenServerUrl;
    int acquireJwt;
    const char *dnsTextUrl;
    int bootTimeRetryWait;
} ParodusCommandConfig;

#endif /* PARODUS_COMMAND_H */