#include <uv.h>
#include <stdio.h>

void callback_timer(uv_timer_t *timer) {
    printf("callback_timer is called(data: %s).\n", timer->data);
}

int main() {
    uv_loop_t *loop = uv_default_loop();
    uv_timer_t timer;
    char *data = "dummy data";

    uv_timer_init(loop, &timer);
    timer.data = data;

    uv_timer_start(&timer, callback_timer, 1000, 0);

    return uv_run(loop, UV_RUN_DEFAULT);
}
