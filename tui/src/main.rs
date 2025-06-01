use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Margin},
    prelude::*,
    widgets::{
        Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Scrollbar,
        ScrollbarOrientation, ScrollbarState,
    },
    Terminal,
};

use std::{f64, io, sync::Arc, time::Duration, u16};
use tokio::sync::{mpsc, Mutex};

const TOTAL_PORTS: usize = 100;

enum ScanMessage {
    PortOpen(u16, String),           // Port and banner
    Vulnerability(u16, Vec<String>), // port, CVEs
    Progress(f64),
}

struct App {
    progress: f64,
    results: Vec<(u16, String)>,
    vulnerabilities: Vec<(u16, String, Vec<String>)>,
    errors: Vec<String>,
    should_quit: bool,
    result_scroll: u16,
    vuln_scroll: u16,
}

impl App {
    fn new() -> Self {
        App {
            progress: 0.0,
            results: Vec::new(),
            vulnerabilities: Vec::new(),
            errors: Vec::new(),
            should_quit: false,
            result_scroll: 0,
            vuln_scroll: 0,
        }
    }
}

async fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: Arc<Mutex<App>>) -> io::Result<()> {
    loop {
        let should_quit = {
            let app_lock = app.lock().await;
            app_lock.should_quit
        };

        if should_quit {
            break;
        }

        let (progress, results, vulnerabilites, errors, result_scroll, vuln_scroll) = {
            let app_lock = app.lock().await;
            (
                app_lock.progress,
                app_lock.results.clone(),
                app_lock.vulnerabilities.clone(),
                app_lock.errors.clone(),
                app_lock.result_scroll,
                app_lock.vuln_scroll,
            )
        };

        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(5),
                    Constraint::Percentage(40),
                    Constraint::Percentage(45),
                    Constraint::Percentage(10),
                ])
                .split(f.area());

            // progress gauge
            let progress_gauge = Gauge::default()
                .block(
                    Block::default()
                        .title("Scan Progress")
                        .borders(Borders::ALL),
                )
                .ratio(progress)
                .label(format!("{:.0}%", progress * 100.0));

            // result list with scrollbar
            let results_items: Vec<ListItem> = results
                .iter()
                .map(|(port, banner)| {
                    ListItem::new(vec![
                        Line::from(format!("[Port {port}]")).fg(Color::Yellow),
                        Line::from(format!("   {banner}")),
                    ])
                })
                .collect();

            let results_list = List::new(results_items)
                .block(Block::default().title("Open Ports").borders(Borders::ALL));

            // vulnerabilities list with scrollbar
            let vuln_items: Vec<ListItem> = vulnerabilites
                .iter()
                .flat_map(|(port, banner, cves)| {
                    let mut items = vec![
                        ListItem::new(Line::from(format!("[Port {port}]")).fg(Color::Yellow)),
                        ListItem::new(Line::from(format!("   Banner: {banner}"))),
                    ];
                    items.extend(cves.iter().map(|cve| {
                        ListItem::new(Line::from(format!("  -  {cve}")).fg(Color::Red))
                    }));
                    items
                })
                .collect();
            let vulns_list = List::new(vuln_items.clone()).block(
                Block::default()
                    .title("Vulnerabilities")
                    .borders(Borders::ALL),
            );

            // errors paragraph
            let errors_par = Paragraph::new(errors.join("\n"))
                .block(Block::default().title("Errors").borders(Borders::ALL));

            // render widget with scrollbar
            f.render_widget(progress_gauge, chunks[0]);

            // results section
            let result_block_area = chunks[1];
            f.render_stateful_widget(
                results_list,
                result_block_area,
                &mut ListState::default().with_selected(Some(result_scroll as usize)),
            );

            let result_scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓"));

            f.render_stateful_widget(
                result_scrollbar,
                result_block_area.inner(Margin {
                    vertical: 1,
                    horizontal: 0,
                }),
                &mut ScrollbarState::new(results.len())
                    .position(result_scroll as usize)
                    .content_length(results.len()),
            );

            // vulns section
            let vuln_block_area = chunks[2];
            let vuln_item_len = vuln_items.len();
            let vuln_viewport_height = vuln_block_area.height.saturating_sub(2);

            f.render_stateful_widget(
                vulns_list,
                vuln_block_area,
                &mut ListState::default().with_selected(Some(vuln_scroll as usize)),
            );

            let vuln_scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓"));

            f.render_stateful_widget(
                vuln_scrollbar,
                vuln_block_area.inner(Margin {
                    vertical: 1,
                    horizontal: 0,
                }),
                &mut ScrollbarState::new(vuln_item_len)
                    .position(vuln_scroll as usize)
                    .content_length(vuln_item_len)
                    .viewport_content_length(vuln_viewport_height as usize),
            );

            f.render_widget(errors_par, chunks[3]);
        })?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => {
                        let mut app_lock = app.lock().await;
                        app_lock.should_quit = true;
                    }
                    KeyCode::Down => {
                        let mut app_lock = app.lock().await;
                        if app_lock.result_scroll < app_lock.results.len() as u16 - 1 {
                            app_lock.result_scroll += 1;
                        }
                    }
                    KeyCode::Up => {
                        let mut app_lock = app.lock().await;
                        if app_lock.result_scroll > 0 {
                            app_lock.result_scroll -= 1;
                        }
                    }
                    KeyCode::PageDown => {
                        let mut app_lock = app.lock().await;
                        app_lock.result_scroll = app_lock.results.len() as u16 - 1;
                    }
                    KeyCode::PageUp => {
                        let mut app_lock = app.lock().await;
                        app_lock.result_scroll = 0;
                    }
                    KeyCode::Char('j') => {
                        let mut app_lock = app.lock().await;

                        app_lock.vuln_scroll = app_lock.vuln_scroll.saturating_add(1);
                        if app_lock.vuln_scroll < app_lock.vulnerabilities.len() as u16 - 1 {
                            app_lock.vuln_scroll += 1;
                        }
                    }
                    KeyCode::Char('k') => {
                        let mut app_lock = app.lock().await;

                        if app_lock.vuln_scroll > 0 {
                            app_lock.vuln_scroll -= 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = Arc::new(Mutex::new(App::new()));
    let (tx, mut rx) = mpsc::channel(32);

    let tx_clone = tx.clone();
    tokio::spawn(async move {
        for i in 1..=TOTAL_PORTS {
            let banner = if i % 3 == 0 {
                "Apache/2.4.49 Server"
            } else if i % 5 == 0 {
                "OpenSSL/1.0.2"
            } else {
                "Generic Service"
            };

            tx_clone
                .send(ScanMessage::PortOpen(i as u16, banner.to_string()))
                .await?;

            let cves = match banner {
                "Apache/2.4.49 Server" => vec![
                    "CVE-2021-41773 (Path Traversal)".to_string(),
                    "CVE-2021-42013 (mod_lua exploit)".to_string(),
                ],
                "OpenSSL/1.0.2" => vec!["CVE-2016-2107 (Padding Oracle)".to_string()],
                _ => vec![],
            };

            if !cves.is_empty() {
                tx_clone
                    .send(ScanMessage::Vulnerability(i as u16, cves))
                    .await?;
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok::<(), anyhow::Error>(())
    });

    // message processing task
    let app_clone = Arc::clone(&app);
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let mut app = app_clone.lock().await;
            match msg {
                ScanMessage::PortOpen(port, banner) => {
                    app.results.push((port, banner));
                    app.progress = app.results.len() as f64 / TOTAL_PORTS as f64;
                }
                ScanMessage::Vulnerability(port, cves) => {
                    let banner_clone = app
                        .results
                        .iter()
                        .find(|(p, _)| *p == port)
                        .map(|(_, banner)| banner.clone());

                    if let Some(banner) = banner_clone {
                        app.vulnerabilities.push((port, banner, cves));
                    }
                }
                ScanMessage::Progress(p) => app.progress = p,
            }
        }
    });

    run_app(&mut terminal, app.clone()).await?;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    Ok(())
}
