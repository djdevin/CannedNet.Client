#include "common.h"

#include "connect_hook.h"

#include "logger.h"
#include "config.h"



connect_t real_connect = NULL;

connect_t original_connect = NULL;


BYTE backup_connect[14];




int WSAAPI hook_connect(
    SOCKET s,
    const struct sockaddr *name,
    int namelen
)
{
    if(!name)
    {
        if(original_connect)
        {
            return original_connect(
                s,
                name,
                namelen
            );
        }

        return SOCKET_ERROR;
    }



    struct sockaddr_in redirect_addr;

    memcpy(
        &redirect_addr,
        name,
        sizeof(struct sockaddr_in)
    );



    char ip[INET_ADDRSTRLEN] = {0};



    if(name->sa_family == AF_INET)
    {
        SOCKADDR_IN *addr =
            (SOCKADDR_IN*)name;



        inet_ntop(
            AF_INET,
            &addr->sin_addr,
            ip,
            sizeof(ip)
        );



        Log(
            "[CONNECT] Socket %d attempting connection to %s:%d",
            s,
            ip,
            ntohs(addr->sin_port)
        );



        //
        // Redirect HTTPS traffic
        //

        if(
            addr->sin_port == htons(443)
        )
        {
            Log(
                "[CONNECT REDIRECT] %s:%d -> %s:%d",
                ip,
                ntohs(addr->sin_port),
                redirect_ip,
                redirect_port
            );



            redirect_addr.sin_addr.s_addr =
                inet_addr(
                    redirect_ip
                );


            redirect_addr.sin_port =
                htons(
                    redirect_port
                );



            name =
                (struct sockaddr*)
                &redirect_addr;
        }
    }




    if(original_connect)
    {
        int ret =
            original_connect(
                s,
                name,
                namelen
            );



        if(
            ret == 0 ||
            (
                ret == SOCKET_ERROR &&
                WSAGetLastError() ==
                    WSAEWOULDBLOCK
            )
        )
        {
            Log(
                "[CONNECT] Socket %d connection established",
                s
            );
        }
        else
        {
            Log(
                "[CONNECT] Socket %d connection FAILED. Error: %d",
                s,
                WSAGetLastError()
            );
        }



        return ret;
    }



    return SOCKET_ERROR;
}