package org.mcc.vulfr.controller;

import org.mcc.vulfr.entity.VulnEnvironment;
import org.mcc.vulfr.service.VulnEnvironmentService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.List;

@RestController
@RequestMapping("/api/environments")
@CrossOrigin(origins = "*", maxAge = 3600)
public class VulnEnvironmentController {

    private final VulnEnvironmentService service;

    public VulnEnvironmentController(VulnEnvironmentService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<List<VulnEnvironment>> getAllEnvironments() {
        return ResponseEntity.ok(service.getAllEnvironments());
    }
    
    @GetMapping("/search")
    public ResponseEntity<Page<VulnEnvironment>> searchEnvironments(
            @RequestParam(defaultValue = "") String keyword,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.ASC, "name"));
        return ResponseEntity.ok(service.searchEnvironments(keyword, pageable));
    }

    @GetMapping("/{id}")
    public ResponseEntity<VulnEnvironment> getEnvironmentById(@PathVariable Long id) {
        return service.getEnvironmentById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/name/{name}")
    public ResponseEntity<VulnEnvironment> getEnvironmentByName(@PathVariable String name) {
        return service.getEnvironmentByName(name)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<?> createEnvironment(@RequestBody VulnEnvironment environment) {
        try {
            VulnEnvironment created = service.createEnvironment(environment);
            return ResponseEntity.status(HttpStatus.CREATED).body(created);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateEnvironment(@PathVariable Long id, @RequestBody VulnEnvironment update) {
        try {
            VulnEnvironment updated = service.updateEnvironment(id, update);
            return ResponseEntity.ok(updated);
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteEnvironment(@PathVariable Long id) {
        try {
            service.deleteEnvironment(id);
            return ResponseEntity.noContent().build();
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/{id}/start")
    public ResponseEntity<VulnEnvironment> startEnvironment(@PathVariable Long id) {
        return ResponseEntity.ok(service.startEnvironment(id));
    }

    @PostMapping("/{id}/stop")
    public ResponseEntity<VulnEnvironment> stopEnvironment(@PathVariable Long id) {
        return ResponseEntity.ok(service.stopEnvironment(id));
    }

    @GetMapping("/{id}/verify")
    public ResponseEntity<Boolean> verifyEnvironment(@PathVariable Long id) {
        return ResponseEntity.ok(service.verifyAccessUrl(id));
    }

    @PostMapping("/{id}/mark-running")
    public ResponseEntity<VulnEnvironment> markAsRunning(@PathVariable Long id) {
        return ResponseEntity.ok(service.markAsRunning(id));
    }

    @PostMapping("/{id}/package")
    public ResponseEntity<?> packageEnvironment(@PathVariable Long id) {
        return ResponseEntity.ok(service.startPackage(id));
    }

    @GetMapping("/{id}/package/status")
    public ResponseEntity<?> getPackageStatus(@PathVariable Long id) {
        return ResponseEntity.ok(service.getPackageStatus(id));
    }

    @GetMapping("/{id}/package/check")
    public ResponseEntity<?> checkPackageExists(@PathVariable Long id) {
        return ResponseEntity.ok(service.checkPackageExists(id));
    }
}