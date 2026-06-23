FROM php:8.5-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends git unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Enable mod_rewrite for Slim routing and mod_headers for security headers.
RUN a2enmod rewrite headers

# Composer (from the official image).
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Always log PHP errors to stderr so they show up in `docker logs`.
COPY docker/php-logging.ini /usr/local/etc/php/conf.d/php-logging.ini

# Point Apache's document root at public/ so Slim's front controller is used.
COPY docker/apache-vhost.conf /etc/apache2/sites-available/000-default.conf

WORKDIR /var/www/html

# Code and vendor/ are mounted at runtime (see docker-compose.yml).
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 80
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["apache2-foreground"]
