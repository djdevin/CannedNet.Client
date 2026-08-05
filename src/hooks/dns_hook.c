#include "common.h"

#include "dns_hook.h"

#include "config.h"
#include "logger.h"
#include "strings.h"
#include "process.h"



getaddrinfo_t real_getaddrinfo = NULL;

getaddrinfo_t original_getaddrinfo = NULL;


gethostbyname_t real_gethostbyname = NULL;


BYTE backup_getaddrinfo[32];



static int redirect_count = 0;



struct hostent *WSAAPI hook_gethostbyname(
    const char *name
)
{
    Log(
        "[HOSTBYNAME] %s",
        name ? name : "NULL"
    );


    if(real_gethostbyname)
        return real_gethostbyname(name);


    return NULL;
}





int WSAAPI hook_getaddrinfo(
    PCSTR node,
    PCSTR service,
    const ADDRINFOA *hints,
    PADDRINFOA *result
)
{
    Log(
        "=============================="
    );


    Log(
        "[DNS REQUEST]"
    );


    Log(
        "[THREAD] %lu",
        GetCurrentThreadId()
    );


    Log(
        "[DNS HOST] %s",
        node ? node : "NULL"
    );


    Log(
        "[DNS SERVICE] %s",
        service ? service : "NULL"
    );


    LogStack();



    //
    // Host rewrite: swap the hostname (e.g. ns.rec.net -> ns.recflare.net) and let real DNS
    // resolve the target's current IP. We don't synthesize a static address, so the redirect
    // survives the target's IP changing.
    //

    char rewritten[256];


    if(
        RewriteHost(
            node,
            rewritten,
            sizeof(rewritten)
        )
    )
    {
        redirect_count++;


        Log(
            "[REDIRECT #%d] %s -> %s (resolving)",
            redirect_count,
            node,
            rewritten
        );


        if(original_getaddrinfo)
        {
            int ret =
                original_getaddrinfo(
                    rewritten,
                    service,
                    hints,
                    result
                );


            if(ret != 0)
                Log(
                    "[DNS FAIL] %s (rewritten, %d)",
                    rewritten,
                    ret
                );


            return ret;
        }


        return EAI_FAIL;
    }





    if(original_getaddrinfo)
    {
        int ret =
            original_getaddrinfo(
                node,
                service,
                hints,
                result
            );



        if(
            ret == 0 &&
            result &&
            *result
        )
        {
            SOCKADDR_IN *addr =
                (SOCKADDR_IN*)
                (*result)->ai_addr;



            char ip[INET_ADDRSTRLEN];


            inet_ntop(
                AF_INET,
                &addr->sin_addr,
                ip,
                sizeof(ip)
            );


            Log(
                "[DNS RESULT] %s -> %s",
                node,
                ip
            );
        }
        else
        {
            Log(
                "[DNS FAIL] %s (%d)",
                node,
                ret
            );
        }



        return ret;
    }



    return EAI_FAIL;
}