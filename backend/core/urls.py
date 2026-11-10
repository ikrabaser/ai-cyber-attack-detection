from django.urls import path

from . import views, views_centrifugo

urlpatterns = [
    path("healthz/", views.healthz),
    path("api/events/", views.ingest),
    path("centrifugo/connect/", views_centrifugo.connect),
    path("centrifugo/refresh/", views_centrifugo.refresh),
    path("centrifugo/subscribe/", views_centrifugo.subscribe),
    path("centrifugo/rpc/", views_centrifugo.rpc),
]
