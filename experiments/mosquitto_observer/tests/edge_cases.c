/* Exact-header callback tests; synthetic fields only, no running broker. */
#include "../observer.c"
#include <assert.h>
#include <stdarg.h>
struct mosquitto { const char *username; const char *id; };
static bool swallow;
static char last_record[2048];
static unsigned log_calls;
const char *mosquitto_client_username(const struct mosquitto *c){return c->username;}
const char *mosquitto_client_id(const struct mosquitto *c){return c->id;}
void mosquitto_log_printf(int level,const char *fmt,...)
{
    va_list args;(void)level;log_calls++;
    if(swallow) return;
    va_start(args,fmt);vsnprintf(last_record,sizeof(last_record),fmt,args);va_end(args);
}
int mosquitto_callback_register(mosquitto_plugin_id_t *id,int event,
    MOSQ_FUNC_generic_callback cb,const void *filter,void *userdata)
{(void)id;(void)event;(void)cb;(void)filter;(void)userdata;return MOSQ_ERR_SUCCESS;}
int main(void)
{
    struct mosquitto_opt opts[]={
        {"username_prefix","poc-"},{"client_id_prefix","poc-"},
        {"topic_prefixes","poc/"},{"events","CONNECT,DISCONNECT,PUBLISH_IN,MESSAGE_OUT,SUBSCRIBE"},
        {"max_events","1000"}};
    struct mosquitto peer={"poc-a","poc-a"};
    struct mosquitto_evt_connect connect={0};
    struct mosquitto_evt_message message={0},before;
    char long_field[300],long_topic[300],scratch[FIELD+3];
    connect.client=&peer;
    assert(mosquitto_plugin_init(NULL,NULL,opts,5)==0);
    assert(observe(MOSQ_EVT_CONNECT,&connect,NULL)==0);
    assert(observe(MOSQ_EVT_MESSAGE_IN,NULL,NULL)==0);
    assert(observe(999,NULL,NULL)==0);
    assert(observe(MOSQ_EVT_MESSAGE_IN,&message,NULL)==0);
    message.client=&peer;
    assert(observe(MOSQ_EVT_MESSAGE_IN,&message,NULL)==0);
    peer.username=NULL;
    assert(observe(MOSQ_EVT_CONNECT,&connect,NULL)==0);
    peer.username="poc-a";
    message.topic="poc/shared";message.qos=3;
    assert(observe(MOSQ_EVT_MESSAGE_IN,&message,NULL)==0);
    assert(malformed==6);
    memset(long_field,'x',sizeof(long_field));memcpy(long_field,"poc-",4);long_field[299]=0;
    memcpy(long_topic,long_field,sizeof(long_topic));long_topic[3]='/';
    peer.id=long_field;message.topic=long_topic;message.qos=1;
    message.payload=(void *)"payload-marker";message.payloadlen=14;
    before=message;
    assert(observe(MOSQ_EVT_MESSAGE_IN,&message,NULL)==0);
    assert(!memcmp(&before,&message,sizeof(message)));
    assert(strstr(last_record,"\"client_id\":null"));
    assert(!strstr(last_record,"payload-marker") && strlen(last_record)<1500);
    assert(!strcmp(json_string("poc/password-marker",scratch),"null"));
    assert(!strcmp(json_string("poc/quote\"marker",scratch),"null"));
    peer.id="poc-a";message.topic="poc/shared";
    swallow=true;before=message;
    assert(observe(MOSQ_EVT_MESSAGE_IN,&message,NULL)==0);
    assert(!memcmp(&before,&message,sizeof(message)));
    swallow=false;
    maximum=emitted;
    unsigned calls=log_calls;
    for(int i=0;i<10;i++) assert(observe(MOSQ_EVT_MESSAGE_IN,&message,NULL)==0);
    assert(dropped==10 && log_calls==calls+1);
    assert(observed==emitted+filtered+malformed+dropped);
    /* Fixed session capacity produces null IDs, not allocations or broker errors. */
    struct mosquitto many[SESSIONS+1];
    memset(sessions,0,sizeof(sessions));
    for(int i=0;i<SESSIONS+1;i++){
        many[i]=peer;
        assert((session_number(&many[i],true,false)!=0)==(i<SESSIONS));
    }
    assert(mosquitto_plugin_cleanup(NULL,NULL,0)==0);
    opts[4].value="0";assert(mosquitto_plugin_init(NULL,NULL,opts,5)==MOSQ_ERR_INVAL);
    opts[4].value="-1";assert(mosquitto_plugin_init(NULL,NULL,opts,5)==MOSQ_ERR_INVAL);
    opts[4].value="100";opts[3].value="ACL_CHECK";
    assert(mosquitto_plugin_init(NULL,NULL,opts,5)==MOSQ_ERR_INVAL);
    opts[3].value="CONNECT";opts[0].key="unknown";
    assert(mosquitto_plugin_init(NULL,NULL,opts,5)==MOSQ_ERR_INVAL);
    puts("EDGE_TESTS PASS null/unsupported/long/unsafe/logger-loss/limit/capacity/invalid-config/no-mutation");
    return 0;
}
