#include "common.h"

#include "config.h"
#include "logger.h"


char redirect_ip[16] = DEFAULT_IP;

int redirect_port = DEFAULT_PORT;


char *redirect_domains[MAX_REDIRECTS];

int redirect_count_config = 0;


char *rewrite_from[MAX_REWRITES];
char *rewrite_to[MAX_REWRITES];

int rewrite_count = 0;


char photon_realtime_appid[64] = "";
char photon_chat_appid[64]     = "";
char photon_voice_appid[64]    = "";

int enable_ssl    = 1;
int enable_http   = 1;
int enable_photon = 1;
int enable_spoof  = 1;
int block_quit    = 0;
int use_hwbp      = 0;   // hardware-breakpoint hooks instead of inline detours -- see include/hwbp.h
int enable_dns    = 1;
int enable_diag   = 0;   // AV logger + hang probe + HWBP self-test; off by default (hang probe
                         // suspends the main thread every 3s). "enableDiag": true to investigate.
int hide_module   = 1;


// Copy the JSON string value for "key" ("key" : "value") from buf into out. No-op if key absent.
static void ScanStringKey(const char *buf, const char *quotedKey, char *out, size_t outlen)
{
    char *k = strstr(buf, quotedKey);
    if(!k) return;
    char *colon = strchr(k, ':');
    if(!colon) return;
    char *start = strchr(colon, '"');
    if(!start) return;
    start++;
    char *end = strchr(start, '"');
    if(!end) return;
    size_t len = (size_t)(end - start);
    if(len >= outlen) return;
    memcpy(out, start, len);
    out[len] = 0;
}

// Reads a JSON boolean value ("key": true / false) from buf into *out. No-op if key absent.
static void ScanBoolKey(const char *buf, const char *quotedKey, int *out)
{
    char *k = strstr(buf, quotedKey);
    if(!k) return;
    char *colon = strchr(k, ':');
    if(!colon) return;
    colon++;
    while(*colon == ' ' || *colon == '\t') colon++;
    if(strncmp(colon, "false", 5) == 0) *out = 0;
    else if(strncmp(colon, "true", 4) == 0) *out = 1;
}



void LoadConfig()
{
    HANDLE hFile =
        CreateFileA(
            CONFIG_FILE,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );


    if(hFile == INVALID_HANDLE_VALUE)
    {
        Log(
            "[CONFIG] No config found, using defaults %s:%d",
            redirect_ip,
            redirect_port
        );

        return;
    }



    DWORD size =
        GetFileSize(
            hFile,
            NULL
        );


    if(size == INVALID_FILE_SIZE)
    {
        CloseHandle(hFile);

        Log(
            "[CONFIG] Failed reading file size"
        );

        return;
    }



    char *buffer =
        calloc(
            1,
            size + 1
        );


    if(!buffer)
    {
        CloseHandle(hFile);

        Log(
            "[CONFIG] Memory allocation failed"
        );

        return;
    }



    DWORD read = 0;


    ReadFile(
        hFile,
        buffer,
        size,
        &read,
        NULL
    );


    CloseHandle(hFile);



    //
    // IP
    //

    char *ip =
        strstr(
            buffer,
            "\"ip\""
        );


    if(ip)
    {
        char *colon =
            strchr(
                ip,
                ':'
            );


        if(colon)
        {
            char *start =
                strchr(
                    colon,
                    '"'
                );


            if(start)
            {
                start++;


                char *end =
                    strchr(
                        start,
                        '"'
                    );


                if(end)
                {
                    size_t len =
                        end - start;


                    if(len < sizeof(redirect_ip))
                    {
                        memcpy(
                            redirect_ip,
                            start,
                            len
                        );


                        redirect_ip[len] = 0;
                    }
                }
            }
        }
    }



    //
    // Port
    //

    char *port =
        strstr(
            buffer,
            "\"port\""
        );


    if(port)
    {
        char *colon =
            strchr(
                port,
                ':'
            );


        if(colon)
        {
            int p =
                atoi(
                    colon + 1
                );


            if(
                p > 0 &&
                p < 65536
            )
            {
                redirect_port = p;
            }
        }
    }




    //
    // Redirect domains
    //

    char *redirect =
        strstr(
            buffer,
            "\"redirect\""
        );


    if(redirect)
    {
        char *array =
            strchr(
                redirect,
                '['
            );


        if(array)
        {
            char *current =
                array;


            while(
                redirect_count_config < MAX_REDIRECTS
            )
            {
                char *q1 =
                    strchr(
                        current,
                        '"'
                    );


                if(!q1)
                    break;


                q1++;


                char *q2 =
                    strchr(
                        q1,
                        '"'
                    );


                if(!q2)
                    break;



                size_t len =
                    q2 - q1;



                redirect_domains[
                    redirect_count_config
                ] =
                    calloc(
                        1,
                        len + 1
                    );


                if(
                    redirect_domains[
                        redirect_count_config
                    ]
                )
                {
                    memcpy(
                        redirect_domains[
                            redirect_count_config
                        ],
                        q1,
                        len
                    );


                    redirect_count_config++;
                }


                current =
                    q2 + 1;
            }
        }
    }



    //
    // Host rewrite pairs: "rewrite": [ { "from": "rec.net", "to": "recflare.net" }, ... ]
    // Scanned sequentially -- within each object "from" precedes "to".
    //

    char *rw =
        strstr(
            buffer,
            "\"rewrite\""
        );


    if(rw)
    {
        char *current = rw;


        while(rewrite_count < MAX_REWRITES)
        {
            //
            // "from" value
            //

            char *fk =
                strstr(current, "\"from\"");

            if(!fk)
                break;


            char *fv1 = strchr(fk + 6, '"');
            if(!fv1) break;
            fv1++;

            char *fv2 = strchr(fv1, '"');
            if(!fv2) break;


            //
            // "to" value (must follow this object's "from")
            //

            char *tk =
                strstr(fv2, "\"to\"");

            if(!tk)
                break;


            char *tv1 = strchr(tk + 4, '"');
            if(!tv1) break;
            tv1++;

            char *tv2 = strchr(tv1, '"');
            if(!tv2) break;


            size_t flen = fv2 - fv1;
            size_t tlen = tv2 - tv1;


            char *fbuf = calloc(1, flen + 1);
            char *tbuf = calloc(1, tlen + 1);


            if(fbuf && tbuf)
            {
                memcpy(fbuf, fv1, flen);
                memcpy(tbuf, tv1, tlen);

                rewrite_from[rewrite_count] = fbuf;
                rewrite_to[rewrite_count]   = tbuf;

                rewrite_count++;
            }
            else
            {
                free(fbuf);
                free(tbuf);
            }


            current = tv2 + 1;
        }
    }



    //
    // Photon Cloud app IDs (optional; injected into AppSettings at connect time).
    //
    ScanStringKey(buffer, "\"photonRealtimeAppId\"", photon_realtime_appid, sizeof(photon_realtime_appid));
    ScanStringKey(buffer, "\"photonChatAppId\"",     photon_chat_appid,     sizeof(photon_chat_appid));
    ScanStringKey(buffer, "\"photonVoiceAppId\"",    photon_voice_appid,    sizeof(photon_voice_appid));

    //
    // Per-hook bisection toggles (all default on). e.g. {"enableSsl": false} to test with the SSL
    // bypass hook disabled.
    //
    ScanBoolKey(buffer, "\"enableSsl\"",    &enable_ssl);
    ScanBoolKey(buffer, "\"enableHttp\"",   &enable_http);
    ScanBoolKey(buffer, "\"enablePhoton\"", &enable_photon);
    ScanBoolKey(buffer, "\"enableSpoof\"",  &enable_spoof);
    ScanBoolKey(buffer, "\"blockQuit\"",    &block_quit);
    ScanBoolKey(buffer, "\"useHwbp\"",      &use_hwbp);
    ScanBoolKey(buffer, "\"enableDns\"",    &enable_dns);
    ScanBoolKey(buffer, "\"enableDiag\"",   &enable_diag);
    ScanBoolKey(buffer, "\"hideModule\"",   &hide_module);


    free(buffer);



    Log(
        "[CONFIG] Photon app ids: realtime=%s chat=%s voice=%s",
        photon_realtime_appid[0] ? photon_realtime_appid : "(none)",
        photon_chat_appid[0]     ? photon_chat_appid     : "(none)",
        photon_voice_appid[0]    ? photon_voice_appid    : "(none)"
    );


    Log(
        "[CONFIG] patches: ssl=%d http=%d photon=%d spoof=%d blockQuit=%d useHwbp=%d dns=%d diag=%d hide=%d",
        enable_ssl, enable_http, enable_photon, enable_spoof, block_quit, use_hwbp, enable_dns, enable_diag, hide_module
    );


    Log(
        "[CONFIG] Loaded %d redirects",
        redirect_count_config
    );


    Log(
        "[CONFIG] Loaded %d host rewrites",
        rewrite_count
    );


    for(
        int i = 0;
        i < rewrite_count;
        i++
    )
    {
        Log(
            "[CONFIG] rewrite %s -> %s",
            rewrite_from[i],
            rewrite_to[i]
        );
    }


    Log(
        "[CONFIG] Redirect IP %s:%d",
        redirect_ip,
        redirect_port
    );



    for(
        int i = 0;
        i < redirect_count_config;
        i++
    )
    {
        Log(
            "[CONFIG] %s",
            redirect_domains[i]
        );
    }
}