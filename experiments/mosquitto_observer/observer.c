/* Optional metadata-only observer, Mosquitto 2.1.2/v5. No auth/ACL callbacks. */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <mosquitto/broker_plugin.h>
#define FIELD 192
#define LIST 8
#define SESSIONS 256
struct selectors { char values[LIST][FIELD]; size_t count; char prefix[FIELD]; };
static struct selectors users, clients, topics;
static bool enabled[5], limit_reported;
static uint64_t maximum, observed, emitted, filtered, malformed, dropped, next_session;
static struct { const struct mosquitto *client; uint64_t id; } sessions[SESSIONS];
static struct timespec start_monotonic;
static const int ids[]={MOSQ_EVT_CONNECT,MOSQ_EVT_DISCONNECT,MOSQ_EVT_MESSAGE_IN,MOSQ_EVT_MESSAGE_OUT,MOSQ_EVT_SUBSCRIBE};
static const char *names[]={"CONNECT","DISCONNECT","PUBLISH_IN","MESSAGE_OUT","SUBSCRIBE"};
/* Reject rather than truncate unsafe/long fields, preventing false correlation. */
static bool safe_string(const char *src,char *out)
{
    char lower[FIELD]; size_t i;
    if(!src) return false;
    for(i=0;i<FIELD-1 && src[i];i++){
        unsigned char c=(unsigned char)src[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||
            c=='_'||c=='-'||c=='.'||c=='/'||c==':')) return false;
        out[i]=(char)c;lower[i]=(char)tolower(c);
    }
    if(!i || src[i]) return false;
    out[i]=0;lower[i]=0;
    return !(strstr(lower,"password")||strstr(lower,"passwd")||strstr(lower,"secret")||
             strstr(lower,"token")||strstr(lower,"credential"));
}
static const char *json_string(const char *src,char *scratch)
{
    char safe[FIELD];
    if(!safe_string(src,safe)) return "null";
    snprintf(scratch,FIELD+3,"\"%s\"",safe);return scratch;
}
static bool matches(const struct selectors *s,const char *v,bool prefixes)
{
    size_t i;
    if(!v) return false;
    if(s->prefix[0] && !strncmp(v,s->prefix,strlen(s->prefix))) return true;
    for(i=0;i<s->count;i++){
        if(prefixes ? !strncmp(v,s->values[i],strlen(s->values[i])) : !strcmp(v,s->values[i])) return true;
    }
    return false;
}
static bool parse_list(struct selectors *s,const char *v)
{
    char buffer[LIST*FIELD],*part,*save=NULL;
    if(!v||!*v||strlen(v)>=sizeof(buffer)||v[0]==','||v[strlen(v)-1]==','||strstr(v,",,")) return false;
    strcpy(buffer,v);
    for(part=strtok_r(buffer,",",&save);part;part=strtok_r(NULL,",",&save)){
        if(s->count==LIST||!safe_string(part,s->values[s->count])) return false;
        s->count++;
    }
    return s->count>0;
}
static bool configure(struct mosquitto_opt *opts,int count)
{
    unsigned seen=0;int i,j;
    memset(&users,0,sizeof(users));memset(&clients,0,sizeof(clients));
    memset(&topics,0,sizeof(topics));memset(enabled,0,sizeof(enabled));maximum=0;
    for(i=0;i<count;i++){
        unsigned bit=0;const char *key=opts[i].key,*v=opts[i].value;
        if(!key||!v) return false;
        if(!strcmp(key,"usernames")){bit=1;if(!parse_list(&users,v)) return false;}
        else if(!strcmp(key,"username_prefix")){bit=2;if(!safe_string(v,users.prefix)) return false;}
        else if(!strcmp(key,"client_ids")){bit=4;if(!parse_list(&clients,v)) return false;}
        else if(!strcmp(key,"client_id_prefix")){bit=8;if(!safe_string(v,clients.prefix)) return false;}
        else if(!strcmp(key,"topic_prefixes")){bit=16;if(!parse_list(&topics,v)) return false;}
        else if(!strcmp(key,"events")){
            struct selectors list={0};bit=32;
            if(!parse_list(&list,v)) return false;
            for(size_t n=0;n<list.count;n++){
                for(j=0;j<5;j++) if(!strcmp(list.values[n],names[j])) break;
                if(j==5||enabled[j]) return false;
                enabled[j]=true;
            }
        }else if(!strcmp(key,"max_events")){
            char *end;bit=64;errno=0;
            for(size_t n=0;v[n];n++) if(v[n]<'0'||v[n]>'9') return false;
            maximum=strtoull(v,&end,10);
            if(errno||!*v||*end||maximum==0||maximum>1000000) return false;
        }else return false;
        if(seen&bit) return false;
        seen|=bit;
    }
    return (seen&112)==112 && (seen&3)!=0 && (seen&12)!=0;
}
static uint64_t session_number(const struct mosquitto *client,bool create,bool remove)
{
    size_t i,vacant=SESSIONS;uint64_t id;
    for(i=0;i<SESSIONS;i++){
        if(sessions[i].client==client){
            id=sessions[i].id;if(remove) sessions[i].client=NULL;return id;
        }
        if(!sessions[i].client) vacant=i;
    }
    if(create&&vacant<SESSIONS){
        sessions[vacant].client=client;sessions[vacant].id=++next_session;return next_session;
    }
    return 0;
}
static void counters(const char *type)
{
    mosquitto_log_printf(MOSQ_LOG_NOTICE,
        "AZTA_OBSERVER {\"schema_version\":2,\"observer_version\":\"a1-h-1\",\"record_type\":\"%s\","
        "\"events_observed\":%" PRIu64 ",\"events_emitted\":%" PRIu64 ",\"events_filtered\":%" PRIu64 ","
        "\"events_malformed_unsupported\":%" PRIu64 ",\"events_dropped_limit\":%" PRIu64 ","
        "\"max_events\":%" PRIu64 ",\"evidence_complete\":%s}",
        type,observed,emitted,filtered,malformed,dropped,maximum,dropped?"false":"true");
}
static int observe(int event,void *data,void *userdata)
{
    const struct mosquitto *client=NULL;const char *topic=NULL,*classification=NULL;
    int idx,qos=-1,reason=-1;uint32_t length=0;bool has_length=false;uint64_t sid;
    char uj[FIELD+3],cj[FIELD+3],tj[FIELD+3],sj[40],qt[16],lt[24],rt[16];
    char utcj[48]="null",monoj[32]="null";struct timespec utc,mono;struct tm tm;
    (void)userdata;observed++;
    for(idx=0;idx<5;idx++) if(ids[idx]==event) break;
    if(idx==5||!data){malformed++;return MOSQ_ERR_SUCCESS;}
    switch(idx){
    case 0:client=((struct mosquitto_evt_connect*)data)->client;classification="authenticated_connection";break;
    case 1:client=((struct mosquitto_evt_disconnect*)data)->client;
        reason=((struct mosquitto_evt_disconnect*)data)->reason;classification="session_closed_origin_unclassified";break;
    case 2:case 3:{
        struct mosquitto_evt_message *m=data;client=m->client;topic=m->topic;qos=m->qos;
        length=m->payloadlen;has_length=true;
        classification=idx==2?"acl_allowed_pre_distribution":"receive_acl_allowed_pre_send";break;
    }
    case 4:{struct mosquitto_evt_subscribe *s=data;client=s->client;
        topic=s->data.topic_filter;qos=s->data.options&3;classification="acl_allowed_pre_apply";break;}
    }
    if(!client||!mosquitto_client_username(client)||!mosquitto_client_id(client)||
       (idx>=2&&(!topic||qos>2||qos<0))){malformed++;return MOSQ_ERR_SUCCESS;}
    if(!matches(&users,mosquitto_client_username(client),false)||
       !matches(&clients,mosquitto_client_id(client),false)){filtered++;return MOSQ_ERR_SUCCESS;}
    sid=session_number(client,idx==0,idx==1);
    if(!enabled[idx]||(topic&&(topic[0]=='$'||!matches(&topics,topic,true)))){filtered++;return MOSQ_ERR_SUCCESS;}
    if(emitted>=maximum){
        dropped++;if(!limit_reported){limit_reported=true;counters("LIMIT_REACHED");}
        return MOSQ_ERR_SUCCESS;
    }
    if(sid) snprintf(sj,sizeof(sj),"\"local-%" PRIu64 "\"",sid);else strcpy(sj,"null");
    if(qos>=0) snprintf(qt,sizeof(qt),"%d",qos);else strcpy(qt,"null");
    if(has_length) snprintf(lt,sizeof(lt),"%" PRIu32,length);else strcpy(lt,"null");
    if(reason>=0) snprintf(rt,sizeof(rt),"%d",reason);else strcpy(rt,"null");
    if(!clock_gettime(CLOCK_REALTIME,&utc)&&gmtime_r(&utc.tv_sec,&tm)){
        char stamp[32];
        if(strftime(stamp,sizeof(stamp),"%Y-%m-%dT%H:%M:%S",&tm))
            snprintf(utcj,sizeof(utcj),"\"%s.%03ldZ\"",stamp,utc.tv_nsec/1000000);
    }
    if(!clock_gettime(CLOCK_MONOTONIC,&mono)) snprintf(monoj,sizeof(monoj),"%" PRId64,
        (int64_t)(mono.tv_sec-start_monotonic.tv_sec)*1000+(mono.tv_nsec-start_monotonic.tv_nsec)/1000000);
    emitted++;
    mosquitto_log_printf(MOSQ_LOG_NOTICE,
        "AZTA_OBSERVER {\"schema_version\":2,\"observer_version\":\"a1-h-1\",\"record_type\":\"EVENT\","
        "\"event_type\":\"%s\",\"broker_event_classification\":\"%s\",\"observer_timestamp_utc\":%s,"
        "\"monotonic_elapsed_ms\":%s,\"username\":%s,\"client_id\":%s,\"session_id\":%s,"
        "\"topic\":%s,\"qos\":%s,\"payload_length\":%s,\"disconnect_reason_code\":%s}",
        names[idx],classification,utcj,monoj,json_string(mosquitto_client_username(client),uj),
        json_string(mosquitto_client_id(client),cj),sj,json_string(topic,tj),qt,lt,rt);
    return MOSQ_ERR_SUCCESS;
}
MOSQUITTO_PLUGIN_DECLARE_VERSION(5)
int mosquitto_plugin_init(mosquitto_plugin_id_t *id,void **userdata,struct mosquitto_opt *opts,int count)
{
    int i,rc;(void)userdata;
    if(!configure(opts,count)){
        mosquitto_log_printf(MOSQ_LOG_ERR,"AZTA_OBSERVER {\"schema_version\":2,\"observer_version\":\"a1-h-1\",\"record_type\":\"CONFIG_ERROR\",\"error\":\"invalid observation configuration\"}");
        return MOSQ_ERR_INVAL;
    }
    observed=emitted=filtered=malformed=dropped=next_session=0;limit_reported=false;
    memset(sessions,0,sizeof(sessions));
    if(clock_gettime(CLOCK_MONOTONIC,&start_monotonic)) return MOSQ_ERR_UNKNOWN;
    /* Broker event-loop callbacks, no worker thread. Register all five to track
     * session lifecycle even if lifecycle output is disabled. */
    for(i=0;i<5;i++){
        rc=mosquitto_callback_register(id,ids[i],observe,NULL,NULL);
        if(rc!=MOSQ_ERR_SUCCESS) return rc;
    }
    return MOSQ_ERR_SUCCESS;
}
int mosquitto_plugin_cleanup(void *userdata,struct mosquitto_opt *opts,int count)
{
    (void)userdata;(void)opts;(void)count;counters("COUNTERS");
    memset(sessions,0,sizeof(sessions));return MOSQ_ERR_SUCCESS;
}
