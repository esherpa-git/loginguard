jQuery(function($) {
    const statusDiv = $('#guard-live-status');
    let lastTs = esherpaGuardData.lastTs;
    let attack = false;
    let countdownInterval = null;

    function initMobileTableScroll() {
        $('table.wp-list-table').each(function() {
            const $table = $(this);
            if (!$table.parent().hasClass('esherpa-table-scroll')) {
                $table.wrap('<div class="esherpa-table-scroll"></div>');
            }
        });

        const $firstWrapper = $('.esherpa-table-scroll').first();
        if ($firstWrapper.length && $('.esherpa-table-scroll-hint').length === 0) {
            const hintText = esherpaGuardData.tableSwipeHint || 'Tipp: Tabelle horizontal wischen/scrollen';
            const $hint = $('<p class="esherpa-table-scroll-hint"></p>').text('↔ ' + hintText);
            $firstWrapper.before($hint);
        }
    }

    function getRandomCalm() {
        const messages = esherpaGuardData.calmMessages;
        return messages[Math.floor(Math.random() * messages.length)];
    }

    function startCountdown(seconds) {
        console.log('startCountdown called with', seconds, 'seconds');
        let remaining = seconds;

        // Stoppe vorherigen Countdown
        if (countdownInterval) {
            clearInterval(countdownInterval);
        }

        function updateCountdown() {
            if (remaining <= 0) {
                clearInterval(countdownInterval);
                location.reload();
                return;
            }

            // Aktualisiere Countdown-Div falls vorhanden
            let countdownDiv = $('#guard-countdown');
            if (countdownDiv.length === 0) {
                countdownDiv = $('<div id="guard-countdown" style="margin-top:10px;font-size:14px;color:#666;"></div>');
                statusDiv.append(countdownDiv);
            }

            const reloadText = esherpaGuardData.autoReloadText || 'Automatische Aktualisierung in %d Sekunden...';
            countdownDiv.html('↻ ' + reloadText.replace('%d', remaining));
            remaining--;
        }

        updateCountdown(); // Sofort erste Anzeige
        countdownInterval = setInterval(updateCountdown, 1000);
    }

    function checkNewFailed() {
        // Stoppe laufenden Countdown bei jedem Check
        if (countdownInterval) {
            clearInterval(countdownInterval);
            countdownInterval = null;
        }

        $.post(esherpaGuardData.ajaxurl, {
            action: 'esherpa_guard_check_new_failed',
            nonce: esherpaGuardData.nonce,
            last_timestamp: lastTs
        }, function(data) {
            if (data.success) {
                if (data.data.new > 0) {
                    lastTs = data.data.latest_ts;
                    attack = true;
                    let msg;
                    if (data.data.new == 1) {
                        msg = '<h2 style="color:#d63638;">' + esherpaGuardData.alarmSingle + '</h2><br><a href="javascript:location.reload();">' + esherpaGuardData.reloadLink + '</a>';
                    } else {
                        msg = '<h2 style="color:#d63638;">' + esherpaGuardData.alarmMulti.replace('%d', data.data.new) + '</h2><a href="javascript:location.reload();">' + esherpaGuardData.reloadLink + '</a>';
                    }
                    statusDiv.html(msg).css({background: '#ffebee', borderLeft: '6px solid #d63638'});

                    // Starte automatischen Countdown
                    console.log('Starting countdown for', data.data.new, 'new attacks');
                    startCountdown(10);
                } else if (!attack) {
                    statusDiv.html(getRandomCalm()).css({background: '#f0f8ff', borderLeft: '6px solid #2271b1'});
                }
            }
        }).fail(function() {
            statusDiv.html(esherpaGuardData.connectionFailed).css({background: '#fff3cd', borderLeft: '6px solid #ffb302'});
        });
    }

    // Copy-to-clipboard Funktion für User-Agents
    function copyToClipboard(text) {
        if (navigator.clipboard && window.isSecureContext) {
            // Modern browsers
            navigator.clipboard.writeText(text).then(function() {
                // Success - could show a tooltip
            });
        } else {
            // Fallback for older browsers
            const textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.position = "fixed";
            textArea.style.left = "-999999px";
            textArea.style.top = "-999999px";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                document.execCommand('copy');
            } catch (err) {
                console.error('Fallback copy failed:', err);
            }
            textArea.remove();
        }
    }

    // Event handler für Copy-Buttons
    $(document).on('click', '.ua-copy-btn', function(e) {
        e.preventDefault();
        e.stopPropagation();
        const userAgent = $(this).data('ua');
        copyToClipboard(userAgent);

        // Visuelles Feedback
        const originalText = $(this).html();
        $(this).html('✓');
        setTimeout(() => {
            $(this).html(originalText);
        }, 1000);
    });

    initMobileTableScroll();
    statusDiv.html(getRandomCalm());
    setInterval(checkNewFailed, 15000);
    checkNewFailed();
});