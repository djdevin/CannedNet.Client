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



    free(buffer);



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