#include "common.h"

#include "strings.h"
#include "config.h"
#include "logger.h"



int ShouldRedirect(const char *host)
{
    if(!host)
        return 0;


    Log(
        "[CHECK] %s",
        host
    );


    for(
        int i = 0;
        i < redirect_count_config;
        i++
    )
    {
        //
        // Exact match
        //

        if(
            _stricmp(
                host,
                redirect_domains[i]
            ) == 0
        )
        {
            Log(
                "[MATCH] %s",
                host
            );

            return 1;
        }



        //
        // Subdomain match
        //

        size_t len =
            strlen(
                redirect_domains[i]
            );


        size_t hostLen =
            strlen(
                host
            );


        if(
            hostLen > len &&
            host[hostLen - len - 1] == '.' &&
            _stricmp(
                host + (hostLen - len),
                redirect_domains[i]
            ) == 0
        )
        {
            Log(
                "[SUBDOMAIN MATCH] %s",
                host
            );

            return 1;
        }
    }


    return 0;
}



int RewriteHost(const char *host, char *out, size_t outlen)
{
    if(!host || !out || outlen == 0)
        return 0;


    for(int i = 0; i < rewrite_count; i++)
    {
        //
        // Exact match only: whole host -> to
        //

        if(_stricmp(host, rewrite_from[i]) == 0)
        {
            const char *to = rewrite_to[i];

            if(strlen(to) + 1 > outlen)
                return 0;

            strcpy_s(out, outlen, to);

            Log("[REWRITE] %s -> %s", host, out);
            return 1;
        }
    }


    return 0;
}