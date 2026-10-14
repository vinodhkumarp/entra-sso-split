package com.example.entrasso.business.api;

import com.example.entrasso.business.generated.api.BusinessApiDelegate;
import com.example.entrasso.business.generated.model.DashboardResponse;
import com.example.entrasso.business.generated.model.ReportsResponse;
import com.example.entrasso.business.security.CanViewDashboard;
import com.example.entrasso.business.security.CanViewReports;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import org.springframework.stereotype.Service;

/** Supplies business behavior to the generated dashboard and reports controller. */
@Service
public class BusinessApiDelegateService implements BusinessApiDelegate {

  /** Returns dashboard data to user, manager, or administrator roles. */
  @Override
  @CanViewDashboard
  public DashboardResponse getDashboard() {
    return new DashboardResponse(
        "Dashboard data returned by the Entra SSO business API",
        List.of("Open tasks: 4", "Reports ready: 2"),
        OffsetDateTime.now(ZoneOffset.UTC));
  }

  /** Returns report summaries only to manager and administrator roles. */
  @Override
  @CanViewReports
  public ReportsResponse getReports() {
    return new ReportsResponse(
        "Reports data returned by the Entra SSO business API",
        List.of("monthly-summary.csv", "security-audit.pdf"),
        OffsetDateTime.now(ZoneOffset.UTC));
  }
}
