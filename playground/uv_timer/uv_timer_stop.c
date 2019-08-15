#include <uv.h>
#include <stdio.h>

void callback_timer1_never_called(uv_timer_t *timer) {
    printf("callback_timer1_never_called is called\n");
}

void callback_timer2_called(uv_timer_t *timer) {
    uv_timer_t *timer1 = timer->data;

    printf("callback_timer2_called is called\n");
    
    uv_timer_stop(timer1);
}

int main() {
    uv_loop_t *loop = uv_default_loop();
    uv_timer_t timer1;
    uv_timer_t timer2;

    uv_timer_init(loop, &timer1);
    uv_timer_init(loop, &timer2);

    timer2.data = &timer1;

    uv_timer_start(&timer1, callback_timer1_never_called, 1000, 0);
    uv_timer_start(&timer2, callback_timer2_called, 500, 0);

    return uv_run(loop, UV_RUN_DEFAULT);
}
