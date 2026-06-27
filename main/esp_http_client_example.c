/* ESP HTTP Client Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdint.h>
#include <string.h>
#include <sys/_types.h>
#include <sys/param.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/unistd.h>
#include "esp_err.h"
#include "esp_log.h"
#include "esp_wifi_types_generic.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "protocol_examples_utils.h"
#include "esp_tls.h"
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include "esp_crt_bundle.h"
#include "driver/gpio.h"
#endif

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"

#include "esp_http_client.h"
#include "esp_wifi.h"
#include "esp_crt_bundle.h"
#include "esp_sntp.h"

#include "cJSON.h"
#include <time.h>

#define LED_GPIO 38

#define MAX_HTTP_RECV_BUFFER 512
#define MAX_HTTP_OUTPUT_BUFFER 2048
static const char *TAG = "HTTP_CLIENT";

/* Bits used to hand off from the event-loop task to scan_task. */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1
static EventGroupHandle_t s_wifi_event_group;

#define MAX_SCAN_AP   20
#define CONNECT_TMO_MS 15000
static const char *TARGET_SSID = "ASK4 Wireless";

/* How many disconnects before we give up. */
#define MAX_RETRY 5
static int s_retry = 0;

typedef struct schedule {
	time_t start;
	uint32_t duration;
} schedule_t;
static schedule_t curr_schedule;

esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    static char *output_buffer;  // Buffer to store response of http request from event handler
    static int output_len;       // Stores number of bytes read
    switch(evt->event_id) {
        case HTTP_EVENT_ERROR:
            ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
            break;
        case HTTP_EVENT_ON_HEADERS_COMPLETE:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADERS_COMPLETE");
            break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            // Clean the buffer in case of a new request
            if (output_len == 0 && evt->user_data) {
                // we are just starting to copy the output data into the use
                memset(evt->user_data, 0, MAX_HTTP_OUTPUT_BUFFER);
            }
            /*
             *  Check for chunked encoding is added as the URL for chunked encoding used in this example returns binary data.
             *  However, event handler can also be used in case chunked encoding is used.
             */
            if (!esp_http_client_is_chunked_response(evt->client)) {
                // If user_data buffer is configured, copy the response into the buffer
                int copy_len = 0;
                if (evt->user_data) {
                    // The last byte in evt->user_data is kept for the NULL character in case of out-of-bound access.
                    copy_len = MIN(evt->data_len, (MAX_HTTP_OUTPUT_BUFFER - output_len));
                    if (copy_len) {
                        memcpy(evt->user_data + output_len, evt->data, copy_len);
                    }
                } else {
                    int content_len = esp_http_client_get_content_length(evt->client);
                    if (output_buffer == NULL) {
                        // We initialize output_buffer with 0 because it is used by strlen() and similar functions therefore should be null terminated.
                        output_buffer = (char *) calloc(content_len + 1, sizeof(char));
                        output_len = 0;
                        if (output_buffer == NULL) {
                            ESP_LOGE(TAG, "Failed to allocate memory for output buffer");
                            return ESP_FAIL;
                        }
                    }
                    copy_len = MIN(evt->data_len, (content_len - output_len));
                    if (copy_len) {
                        memcpy(output_buffer + output_len, evt->data, copy_len);
                    }
                }
                output_len += copy_len;
            }else{
				if (evt->user_data) {
			        if (output_len == 0) {
			            memset(evt->user_data, 0, MAX_HTTP_OUTPUT_BUFFER);
			        }
			        int copy_len = MIN(evt->data_len, MAX_HTTP_OUTPUT_BUFFER - output_len);
			        if (copy_len > 0) {
			            memcpy((char *)evt->user_data + output_len, evt->data, copy_len);
			            output_len += copy_len;
			        }
			    }
			}

            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            if (output_buffer != NULL) {
#if CONFIG_EXAMPLE_ENABLE_RESPONSE_BUFFER_DUMP
                ESP_LOG_BUFFER_HEX(TAG, output_buffer, output_len);
#endif
                free(output_buffer);
                output_buffer = NULL;
            }
            output_len = 0;
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            int mbedtls_err = 0;
            esp_err_t err = esp_tls_get_and_clear_last_error((esp_tls_error_handle_t)evt->data, &mbedtls_err, NULL);
            if (err != 0) {
                ESP_LOGI(TAG, "Last esp error code: 0x%x", err);
                ESP_LOGI(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
            }
            if (output_buffer != NULL) {
                free(output_buffer);
                output_buffer = NULL;
            }
            output_len = 0;
            break;
        case HTTP_EVENT_REDIRECT:
            ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
            esp_http_client_set_header(evt->client, "From", "user@example.com");
            esp_http_client_set_header(evt->client, "Accept", "text/html");
            esp_http_client_set_redirection(evt->client);
            break;
        default:
            break;
    }
    return ESP_OK;
}

/* -------------------------------------------------------------------------
 * Event handler. Runs in the EVENT LOOP TASK context (not scan_task).
 * Keep it short: just signal bits or kick a retry. No long blocking here.
 * ---------------------------------------------------------------------- */
static void event_handler(void *arg, esp_event_base_t base,
                          int32_t id, void *event_data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        /* Driver is up. scan_task will drive scan + connect. */
        ESP_LOGI(TAG, "STA started");
 
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *d = event_data;
        ESP_LOGW(TAG, "disconnected, reason %d", d->reason);
        if (s_retry < MAX_RETRY) {
            s_retry++;
            esp_wifi_connect();                 /* retry */
            ESP_LOGI(TAG, "retry %d/%d", s_retry, MAX_RETRY);
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
 
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = event_data;
        ESP_LOGI(TAG, "got IP " IPSTR, IP2STR(&e->ip_info.ip));
        s_retry = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static time_t iso8601_to_unix(const char *iso)
{
    struct tm tm = {0};
    int year, mon, mday, hour, min, sec;

    if (sscanf(iso, "%d-%d-%dT%d:%d:%d",
               &year, &mon, &mday, &hour, &min, &sec) != 6) {
        return (time_t)-1;   // parse failure
    }

    tm.tm_year = year - 1900;
    tm.tm_mon  = mon  - 1;
    tm.tm_mday = mday;
    tm.tm_hour = hour;
    tm.tm_min  = min;
    tm.tm_sec  = sec;

    return timegm(&tm);   // interpret as UTC (the trailing Z)
}

static void parse_schedule(const char *json, schedule_t *schedule)
{
    cJSON *root = cJSON_Parse(json);
    if (root == NULL) {
        ESP_LOGE(TAG, "JSON parse failed: %s",
                 cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "?");
        return;
    }

    cJSON *id    = cJSON_GetObjectItem(root, "id");
    cJSON *start = cJSON_GetObjectItem(root, "start");
    cJSON *dur   = cJSON_GetObjectItem(root, "durationSec");

    const char *id_str    = cJSON_IsString(id)    ? id->valuestring    : "?";
    const char *start_str = cJSON_IsString(start) ? start->valuestring : "?";
    int duration_sec      = cJSON_IsNumber(dur)   ? dur->valueint      : 0;

    ESP_LOGI(TAG, "id=%s start=%s durationSec=%d",
             id_str, start_str, duration_sec);
	
	schedule->start = iso8601_to_unix(start->valuestring);
	schedule->duration = dur->valueint;

    cJSON_Delete(root);
}

static void print_rtc(void)
{
    time_t now = 0;
    struct tm timeinfo = {0};
    time(&now);
    localtime_r(&now, &timeinfo);   // gmtime_r for UTC

    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &timeinfo);
    ESP_LOGI(TAG, "RTC: %s (epoch %lld)", buf, (long long)now);
}

static void sync_time(void)
{
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_init();

    // wait for a plausible time (post-2020)
    time_t now = 0;
    struct tm ti = {0};
    int retry = 0;
    while (ti.tm_year < (2020 - 1900) && ++retry < 20) {
        vTaskDelay(pdMS_TO_TICKS(500));
        time(&now);
        localtime_r(&now, &ti);
    }
}

static void blink_and_greet(void)
{
    gpio_reset_pin(LED_GPIO);
    gpio_set_direction(LED_GPIO, GPIO_MODE_OUTPUT);

    for (int i = 0; i < 3; i++) {
        gpio_set_level(LED_GPIO, 1);
        vTaskDelay(pdMS_TO_TICKS(200));
        gpio_set_level(LED_GPIO, 0);
        vTaskDelay(pdMS_TO_TICKS(200));
    }
 
    printf("hello world\n");   // goes to console UART (UART0)
}

/* -------------------------------------------------------------------------
 * scan_task: scan, confirm the OPEN ASK4 SSID is present, then connect
 * and block until the event handler signals success or failure.
 * ---------------------------------------------------------------------- */
static void scan_task(void *pv)
{
	wifi_config_t config = {0};
	wifi_scan_config_t scan_cfg = {
        .ssid = NULL,           /* scan all, then filter ourselves */
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
    };
	ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_cfg, true)); 
	
	uint16_t n = MAX_SCAN_AP;
    wifi_ap_record_t records[MAX_SCAN_AP];
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&n, records));
    ESP_LOGI(TAG, "found %d APs", n);

    bool found_ssid = false;
    for (int i = 0; i < n; i++) {
        if (strcmp((char *)records[i].ssid, TARGET_SSID) == 0 &&
            records[i].authmode == WIFI_AUTH_OPEN) {
            found_ssid = true;
			break;
        }
    }
    if (!found_ssid) {
        printf("%s not in range\n", TARGET_SSID);
        vTaskDelete(NULL);
        return;
    }
	
	ESP_ERROR_CHECK(esp_wifi_get_config(WIFI_IF_STA, &config));
	strlcpy((char *)config.sta.ssid, TARGET_SSID, sizeof(config.sta.ssid));
	config.sta.failure_retry_cnt = 4;
	memset(config.sta.password, 0, sizeof(config.sta.password));
	config.sta.threshold.authmode = WIFI_AUTH_OPEN;      // critical for open APs
	config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
	config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
	config.sta.bssid_set = false;
	ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &config));
	
	/* --- 4. Connect and WAIT on the event group (no polling) --- */
    xEventGroupClearBits(s_wifi_event_group,
                         WIFI_CONNECTED_BIT | WIFI_FAIL_BIT);
    printf("connecting to %s,\n", config.sta.ssid);
    ESP_ERROR_CHECK(esp_wifi_connect());
	
	EventBits_t bits = xEventGroupWaitBits(
	    s_wifi_event_group,                  // 1. which group
	    WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,  // 2. bits to wait for
	    pdFALSE,                             // 3. clear-on-exit?
	    pdFALSE,                             // 4. wait for ALL bits?
	    pdMS_TO_TICKS(CONNECT_TMO_MS));      // 5. max time to block
	
	if (bits & WIFI_CONNECTED_BIT) {
        /* Associated + got IP. Read AP info WITHOUT ESP_ERROR_CHECK. */
        wifi_ap_record_t ap;
        esp_err_t err = esp_wifi_sta_get_ap_info(&ap);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Connected to %.32s  rssi %d", ap.ssid, ap.rssi);
        } else {
            ESP_LOGW(TAG, "get_ap_info: %s", esp_err_to_name(err));
        }
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "failed to connect after %d retries", MAX_RETRY);
    } else {
        ESP_LOGE(TAG, "connect timeout (%d ms)", CONNECT_TMO_MS);
    }
 
    vTaskDelete(NULL);   /* one-shot task */
}

static void get_schedule(void *pv)
{
    xEventGroupWaitBits(s_wifi_event_group, WIFI_CONNECTED_BIT,
                        pdFALSE, pdTRUE, portMAX_DELAY);
	char resp[MAX_HTTP_OUTPUT_BUFFER + 1] = {0};
    esp_http_client_config_t config = {
        .url = "https://ardenpalme.com/api/garden",
        .event_handler = _http_event_handler,
        .user_data = resp,
        .timeout_ms = 5000,
		.crt_bundle_attach = esp_crt_bundle_attach,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

	sync_time();
    /* API key as a header — set before perform() */
	esp_http_client_set_header(client, "X-API-Key", "cU40m36H4kzZUH7y");
	
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "status %d, body: %s",
                 esp_http_client_get_status_code(client), resp);
		parse_schedule(resp, &curr_schedule);
		print_rtc();
    } else {
        ESP_LOGE(TAG, "GET failed: %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
    vTaskDelete(NULL);
}

static void wifi_init(void)
{
    s_wifi_event_group = xEventGroupCreate();
 
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
 
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
 
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, NULL));
 
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());   /* fires WIFI_EVENT_STA_START */
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
	
	wifi_init();
	xTaskCreate(get_schedule, "http", 8192, NULL, 5, NULL);
	xTaskCreate(scan_task, "scan_task", 4096, NULL, 5, NULL);
}
