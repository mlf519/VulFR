package org.mcc.vulfr.repository;

import org.mcc.vulfr.entity.VulnEnvironment;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface VulnEnvironmentRepository extends JpaRepository<VulnEnvironment, Long> {
    Optional<VulnEnvironment> findByName(String name);
    boolean existsByName(String name);
    boolean existsByPort(Integer port);
    long countByStatus(String status);
    
    @Query("SELECT e FROM VulnEnvironment e WHERE " +
           "(:keyword IS NULL OR :keyword = '' OR e.name LIKE %:keyword% OR e.cveId LIKE %:keyword%)")
    Page<VulnEnvironment> searchByNameOrCveId(@Param("keyword") String keyword, Pageable pageable);
    
    long countByNameContainingOrCveIdContaining(String name, String cveId);
}
